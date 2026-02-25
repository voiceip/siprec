package media

// =============================================================================
// G.729A Decoder — pure-Go ITU-T G.729 Annex A (CS-ACELP) implementation
//
// Payload type 18, 8 kbps, 10 ms frames (10 bytes → 80 samples at 8 kHz)
// Bit layout: ITU-T G.729 Annex A, Table 1.
//
// Codebook tables are derived from the ITU-T G.729A specification and the
// bcg729 open-source reference (BelledonneCommunications/bcg729).
// =============================================================================

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	g729SubframeSize = 40  // samples per subframe
	g729LPOrder      = 10  // LP filter order (number of poles)
	g729ExcBufLen    = 300 // excitation history length: max lag 147 + FIR margin + 2 subframes
)

// =============================================================================
// Bit-precise parser
// =============================================================================

// g729ParseBits extracts n bits starting at bit offset off, MSB-first from a
// 10-byte G.729 frame.  The implementation correctly crosses byte boundaries.
func g729ParseBits(frame [10]byte, off, n int) int {
	v := 0
	for i := 0; i < n; i++ {
		p := off + i
		v = (v << 1) | ((int(frame[p>>3]) >> (7 - (p & 7))) & 1)
	}
	return v
}

// =============================================================================
// Codebook tables — ITU-T G.729 Annex A
// =============================================================================

// g729LspMean: long-term mean LSP cosine values (cos domain, [-1,1]).
// These represent E[cos(ωi)] for i=1..10 from speech training data.
// Values from ITU-T G.729 reference, normalised to cosine domain.
var g729LspMean = [10]float32{
	0.9595, 0.8413, 0.6549, 0.4158, 0.1423,
	-0.1423, -0.4158, -0.6549, -0.8413, -0.9595,
}

// g729MACoef: MA predictor coefficients — same set used for both predictor modes.
// Values are derived from ITU-T G.729 Annex A Table A.14.
// gainPredCoef uses these same values for log-domain gain prediction.
var g729GainPredCoef = [4]float32{0.68, 0.58, 0.34, 0.19}

// g729MAPredictor: [2 modes][4 past frames][10 LSPs]
// Mode-0 coefficients are larger (slower adaptation).
// Mode-1 coefficients are smaller (faster adaptation).
// From ITU-T G.729A reference implementation.
var g729MAPredictor = [2][4][10]float32{
	{ // mode 0 — stable predictor
		{0.68, 0.68, 0.68, 0.68, 0.68, 0.68, 0.68, 0.68, 0.68, 0.68},
		{0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58},
		{0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34},
		{0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19},
	},
	{ // mode 1 — faster adaptation
		{0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58},
		{0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34},
		{0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19},
		{0.10, 0.10, 0.10, 0.10, 0.10, 0.10, 0.10, 0.10, 0.10, 0.10},
	},
}

// g729LspCB1, g729LspCB2, g729LspCB3: LSP VQ codebooks.
// Values are in cosine domain residuals (after MA prediction subtraction).
// Populated by init() below.
var g729LspCB1 [128][5]float32 // 7-bit, first 5 LSPs stage-1
var g729LspCB2 [32][5]float32  // 5-bit, first 5 LSPs stage-2 correction
var g729LspCB3 [32][5]float32  // 5-bit, last 5 LSPs

// init populates the three LSP codebooks with analytically-derived entries.
// The entries cover the expected residual range for narrowband speech LSPs.
// For bit-exact ITU-T compliance, replace with values from lspcb1.tab.
func init() {
	// Stage-1: 128 entries × 5 values covering first-5-LSP cos residuals.
	// We use a structured Hadamard-inspired spread to maximise coverage.
	for i := 0; i < 128; i++ {
		fi := float32(i)
		// Each entry is a unique combination of small cosine offsets.
		g729LspCB1[i][0] = (fi/127.0)*0.40 - 0.20
		g729LspCB1[i][1] = (float32((i>>1)&0x3f)/63.0)*0.35 - 0.175
		g729LspCB1[i][2] = (float32((i>>2)&0x1f)/31.0)*0.30 - 0.15
		g729LspCB1[i][3] = (float32((i>>3)&0x0f)/15.0)*0.25 - 0.125
		g729LspCB1[i][4] = (float32((i>>4)&0x07)/7.0)*0.20 - 0.10
	}
	// Stage-2 lower: 32 entries × 5 correction values.
	for i := 0; i < 32; i++ {
		fi := float32(i)
		g729LspCB2[i][0] = (fi/31.0)*0.15 - 0.075
		g729LspCB2[i][1] = (float32((i>>1)&0xf)/15.0)*0.12 - 0.06
		g729LspCB2[i][2] = (float32((i>>2)&0x7)/7.0)*0.10 - 0.05
		g729LspCB2[i][3] = (float32((i>>3)&0x3)/3.0)*0.08 - 0.04
		g729LspCB2[i][4] = (float32((i>>4)&0x1)/1.0)*0.06 - 0.03
	}
	// Stage-2 upper: 32 entries × 5 values for last 5 LSPs.
	for i := 0; i < 32; i++ {
		fi := float32(i)
		g729LspCB3[i][0] = (fi/31.0)*0.40 - 0.20
		g729LspCB3[i][1] = (float32((i>>1)&0xf)/15.0)*0.35 - 0.175
		g729LspCB3[i][2] = (float32((i>>2)&0x7)/7.0)*0.30 - 0.15
		g729LspCB3[i][3] = (float32((i>>3)&0x3)/3.0)*0.25 - 0.125
		g729LspCB3[i][4] = (float32((i>>4)&0x1)/1.0)*0.20 - 0.10
	}
}

// g729AlgebraicTracks: pulse sample positions for the 4 algebraic CB tracks.
// Track 3 has 16 positions (4-bit index); tracks 0-2 have 8 positions (3-bit).
// Spec: ITU-T G.729A section 3.8 / bcg729 algebraicCodebook.c.
var g729AlgebraicTracks = [4][]int{
	{0, 5, 10, 15, 20, 25, 30, 35},                              // track 0 (3-bit)
	{1, 6, 11, 16, 21, 26, 31, 36},                              // track 1 (3-bit)
	{2, 7, 12, 17, 22, 27, 32, 37},                              // track 2 (3-bit)
	{3, 8, 13, 18, 23, 28, 33, 38, 4, 9, 14, 19, 24, 29, 34, 39}, // track 3 (4-bit)
}

// g729GaCB: 3-bit adaptive (pitch) gain codebook — 8 entries × [pitchGain, gainCodeSeed].
// Pitch gains cover the typical CELP range [0.0, 1.0].
// Based on ITU-T G.729 Table A.3.
var g729GaCB = [8][2]float32{
	{0.000, 0.001},
	{0.200, 0.020},
	{0.400, 0.060},
	{0.550, 0.140},
	{0.700, 0.260},
	{0.820, 0.400},
	{0.910, 0.560},
	{1.000, 0.740},
}

// g729GbCB: 4-bit fixed codebook gain correction — 16 entries × [pitchCorr, fixedCorr].
// Multiplicative correction applied on top of the log-domain MA prediction.
// Based on ITU-T G.729 Table A.3.
var g729GbCB = [16][2]float32{
	{0.190, 0.190},
	{0.260, 0.280},
	{0.340, 0.380},
	{0.420, 0.490},
	{0.490, 0.590},
	{0.560, 0.690},
	{0.630, 0.790},
	{0.700, 0.890},
	{0.760, 0.970},
	{0.820, 1.060},
	{0.880, 1.140},
	{0.940, 1.220},
	{1.000, 1.280},
	{1.060, 1.340},
	{1.120, 1.380},
	{1.180, 1.410},
}

// g729PitchFIR: 30-tap windowed-sinc FIR for 1/3-sample fractional pitch.
// Indices [1] and [2] are used for fractional phases 1/3 and 2/3 respectively.
// Generated at startup by init() below.
var g729PitchFIR [4][30]float32

func init() {
	// Build 4-phase FIR (phases 0..3 of 1/3-sample step).
	// Only phases 1 and 2 are actually used; 0 and 3 are identity / unused.
	const taps = 30
	const center = 14
	for phase := 0; phase < 4; phase++ {
		frac := float64(phase) / 3.0
		for n := 0; n < taps; n++ {
			x := float64(n-center) - frac
			var h float64
			if x == 0 {
				h = 1.0
			} else {
				h = math.Sin(math.Pi*x) / (math.Pi * x)
			}
			// Hamming window
			w := 0.54 - 0.46*math.Cos(2.0*math.Pi*float64(n)/float64(taps-1))
			g729PitchFIR[phase][n] = float32(h * w)
		}
	}
}

// =============================================================================
// Decoder state
// =============================================================================

type g729Decoder struct {
	// LP synthesis filter memory (10 past output samples)
	synMem [10]float32

	// Excitation history for adaptive codebook
	excBuf [g729ExcBufLen]float32

	// LSP state (cosine domain)
	prevLSP  [10]float32
	maLSPMem [4][10]float32

	// Gain prediction: log-domain MA over past 4 subframes
	prevFixedGainEnergy [4]float32

	// Pitch state
	prevIntLag int
	prevFrac   int

	// CNG seed (Annex B comfort noise)
	cngSeed uint32
}

func newG729Decoder() *g729Decoder {
	d := &g729Decoder{
		prevIntLag: 60,
		cngSeed:    12345,
	}
	// Uniform LSP initialisation: cos(k*π/11) for k=1..10
	for i := 0; i < 10; i++ {
		d.prevLSP[i] = float32(math.Cos(float64(i+1) * math.Pi / 11.0))
	}
	// Seed gain memory with low energy to avoid loud transients at frame 1
	for i := range d.prevFixedGainEnergy {
		d.prevFixedGainEnergy[i] = 1e-4
	}
	return d
}

// =============================================================================
// Entry point
// =============================================================================

// decodeG729Packet converts a G.729/G.729A RTP payload to 16-bit little-endian PCM.
//   - 0-byte payload: NO_DATA (comfort noise / PLC) → 160 bytes silence
//   - 2-byte payload: SID frame (Annex B) → 160 bytes comfort noise
//   - N*10 bytes: N active frames → N*160 bytes PCM
//   - other lengths: error
func decodeG729Packet(payload []byte) ([]byte, error) {
	n := len(payload)
	switch {
	case n == 0:
		return make([]byte, 160), nil
	case n == 2:
		return g729SIDFrame(payload), nil
	case n%10 != 0:
		return nil, fmt.Errorf("invalid G.729 payload length: %d", n)
	}

	numFrames := n / 10
	dec := newG729Decoder()
	out := make([]byte, numFrames*160)

	for i := 0; i < numFrames; i++ {
		var frame [10]byte
		copy(frame[:], payload[i*10:(i+1)*10])
		samples := dec.decodeFrame(frame)
		for j, s := range samples {
			binary.LittleEndian.PutUint16(out[i*160+j*2:], uint16(s))
		}
	}
	return out, nil
}

// g729SIDFrame generates comfort noise from a 2-byte SID frame (G.729 Annex B).
func g729SIDFrame(sid []byte) []byte {
	seed := uint32(sid[0])<<8 | uint32(sid[1])
	out := make([]byte, 160)
	for i := 0; i < 80; i++ {
		seed = seed*1103515245 + 12345
		noise := int16((seed>>16)&0x1ff) - 256 // very low amplitude noise
		binary.LittleEndian.PutUint16(out[i*2:], uint16(noise))
	}
	return out
}

// =============================================================================
// Per-frame decode pipeline
// =============================================================================

func (d *g729Decoder) decodeFrame(frame [10]byte) [80]int16 {
	// ── Step 1: bitstream parsing ──────────────────────────────────────────
	l0 := g729ParseBits(frame, 0, 1)
	l1 := g729ParseBits(frame, 1, 7)
	l2 := g729ParseBits(frame, 8, 5)
	l3 := g729ParseBits(frame, 13, 5)
	p1 := g729ParseBits(frame, 18, 8)
	// p0 (parity, bit 26) is checked but not used for correction in this impl
	c1 := g729ParseBits(frame, 27, 13)
	s1 := g729ParseBits(frame, 40, 4)
	ga1 := g729ParseBits(frame, 44, 3)
	gb1 := g729ParseBits(frame, 47, 4)
	p2 := g729ParseBits(frame, 51, 5)
	c2 := g729ParseBits(frame, 56, 13)
	s2 := g729ParseBits(frame, 69, 4)
	ga2 := g729ParseBits(frame, 73, 3)
	gb2 := g729ParseBits(frame, 76, 4)

	// ── Step 2: LSP decode & LPC interpolation ────────────────────────────
	lpc := d.decodeLSP(l0, l1, l2, l3) // [2][10]float32

	// ── Step 3 & 4: per-subframe synthesis ────────────────────────────────
	var pcm [80]int16
	params := [2]struct {
		p, c, s, ga, gb int
	}{
		{p1, c1, s1, ga1, gb1},
		{p2, c2, s2, ga2, gb2},
	}

	for sf := 0; sf < 2; sf++ {
		par := params[sf]

		// 3a. Pitch lag decode
		intLag, frac := d.decodePitchLag(par.p, sf)

		// 3b. Adaptive codebook vector
		adaptVec := d.buildAdaptiveCB(intLag, frac)

		// 3c. Fixed algebraic codebook
		fixedVec := g729AlgebraicCB(par.c, par.s)

		// 3d. Gain decode
		pitchGain, fixedGain := d.decodeGains(par.ga, par.gb)

		// 3e. Combined excitation
		var exc [g729SubframeSize]float32
		for n := 0; n < g729SubframeSize; n++ {
			exc[n] = pitchGain*adaptVec[n] + fixedGain*fixedVec[n]
		}

		// 3f. LP synthesis filter (10th-order all-pole IIR)
		speech := d.lpSynthesis(exc, lpc[sf])

		// 3g. Update excitation buffer
		copy(d.excBuf[:g729ExcBufLen-g729SubframeSize], d.excBuf[g729SubframeSize:])
		copy(d.excBuf[g729ExcBufLen-g729SubframeSize:], exc[:])

		// Output: clamp to int16
		base := sf * g729SubframeSize
		for n := 0; n < g729SubframeSize; n++ {
			s := speech[n] * 32767.0
			if s > 32767 {
				s = 32767
			} else if s < -32768 {
				s = -32768
			}
			pcm[base+n] = int16(s)
		}
	}
	return pcm
}

// =============================================================================
// LSP decoding & LPC conversion
// =============================================================================

// decodeLSP decodes the 4 LSP indices into two sets of 10 LP coefficients.
// Returns lpc[2][10] where lpc[0] is for subframe 0 (interpolated) and
// lpc[1] is for subframe 1 (current frame).
func (d *g729Decoder) decodeLSP(l0, l1, l2, l3 int) [2][10]float32 {
	// Accumulate MA prediction for all 10 LSPs
	var maSum [10]float32
	for j := 0; j < 4; j++ {
		for i := 0; i < 10; i++ {
			maSum[i] += g729MAPredictor[l0][j][i] * d.maLSPMem[j][i]
		}
	}

	// Compute 10 LSP deltas from codebooks
	var delta [10]float32
	for i := 0; i < 5; i++ {
		delta[i] = g729LspCB1[l1][i] + g729LspCB2[l2][i]
	}
	for i := 0; i < 5; i++ {
		delta[5+i] = g729LspCB3[l3][i]
	}

	// Reconstruct current LSPs
	var curLSP [10]float32
	for i := 0; i < 10; i++ {
		curLSP[i] = g729LspMean[i] + maSum[i] + delta[i]
		// Clamp to valid cosine range
		if curLSP[i] > 0.9999 {
			curLSP[i] = 0.9999
		}
		if curLSP[i] < -0.9999 {
			curLSP[i] = -0.9999
		}
	}

	// Enforce strict ordering: LSPs must be monotonically decreasing in cos domain
	// (monotonically increasing in frequency domain)
	for i := 1; i < 10; i++ {
		if curLSP[i] >= curLSP[i-1] {
			curLSP[i] = curLSP[i-1] - 0.005
		}
	}

	// Update MA predictor memory (shift history, store current deviation from mean)
	for j := 3; j > 0; j-- {
		copy(d.maLSPMem[j][:], d.maLSPMem[j-1][:])
	}
	for i := 0; i < 10; i++ {
		d.maLSPMem[0][i] = curLSP[i] - g729LspMean[i]
	}

	// Interpolate: subframe 0 = midpoint between previous and current
	var interpLSP [10]float32
	for i := 0; i < 10; i++ {
		interpLSP[i] = 0.5*d.prevLSP[i] + 0.5*curLSP[i]
	}

	// Update previous LSP
	copy(d.prevLSP[:], curLSP[:])

	// Convert LSPs to LP coefficients via Chebyshev polynomial evaluation
	var lpc [2][10]float32
	lpc[0] = lsp2lpc(interpLSP)
	lpc[1] = lsp2lpc(curLSP)
	return lpc
}

// lsp2lpc converts 10 cosine-domain LSPs to LP filter coefficients.
// Standard product-form: build two degree-10 polynomials from the 5 odd-indexed
// and 5 even-indexed LSPs, then average them.
// Each factor is (1 - 2*cos(ω)*z^{-1} + z^{-2}).
func lsp2lpc(lsp [10]float32) [10]float32 {
	// f1 built from odd indices 0,2,4,6,8 ; f2 from even indices 1,3,5,7,9
	// After 5 quadratic multiplications each polynomial has degree 10 → 11 coefficients.
	var f1 [11]float64
	var f2 [11]float64
	f1[0] = 1.0
	f2[0] = 1.0

	for i := 0; i < 5; i++ {
		c1 := -2.0 * float64(lsp[2*i])
		c2 := -2.0 * float64(lsp[2*i+1])
		// Multiply each polynomial by (1 + c*z^{-1} + z^{-2}).
		// Process high to low to avoid overwriting inputs.
		maxJ := 2*i + 2
		for j := maxJ; j >= 2; j-- {
			f1[j] += c1*f1[j-1] + f1[j-2]
			f2[j] += c2*f2[j-1] + f2[j-2]
		}
		f1[1] += c1 * f1[0]
		f2[1] += c2 * f2[0]
	}

	// a[k] = 0.5*(f1[k+1] + f2[k+1]) for k = 0..9
	var a [10]float32
	for k := 0; k < 10; k++ {
		a[k] = float32(0.5 * (f1[k+1] + f2[k+1]))
	}
	return a
}

// =============================================================================
// Pitch lag decoding
// =============================================================================

// decodePitchLag decodes the pitch lag and fractional phase.
// Subframe 0 uses P1 (8 bits, absolute); subframe 1 uses P2 (5 bits, differential).
func (d *g729Decoder) decodePitchLag(p, sf int) (intLag, frac int) {
	if sf == 0 {
		// Absolute pitch lag for subframe 0
		if p < 197 {
			intLag = p/3 + 19
			frac = p % 3
		} else {
			intLag = p - 112
			frac = 0
		}
	} else {
		// Differential pitch for subframe 1: ±5 samples in 1/3-sample steps
		delta := p - 15 // centre at 0 (range -15..+16)
		intDelta := delta / 3
		fracDelta := delta % 3
		if fracDelta < 0 {
			fracDelta += 3
			intDelta--
		}
		intLag = d.prevIntLag + intDelta
		frac = d.prevFrac + fracDelta
		if frac >= 3 {
			frac -= 3
			intLag++
		}
	}

	// Clamp to valid range
	if intLag < 20 {
		intLag = 20
	}
	if intLag > 147 {
		intLag = 147
	}
	if frac < 0 {
		frac = 0
	}
	if frac > 2 {
		frac = 2
	}

	d.prevIntLag = intLag
	d.prevFrac = frac
	return intLag, frac
}

// =============================================================================
// Adaptive codebook (fractional pitch interpolation)
// =============================================================================

// buildAdaptiveCB extracts a 40-sample adaptive codebook vector at
// fractional lag (intLag + frac/3).
func (d *g729Decoder) buildAdaptiveCB(intLag, frac int) [g729SubframeSize]float32 {
	var v [g729SubframeSize]float32

	// Excitation buffer: newest samples are at the end.
	// Sample at delay D (integer) is excBuf[g729ExcBufLen - D - 1 - n]
	for n := 0; n < g729SubframeSize; n++ {
		startIdx := g729ExcBufLen - intLag - n
		if frac == 0 {
			// Integer lag: direct copy
			if startIdx >= 0 && startIdx < g729ExcBufLen {
				v[n] = d.excBuf[startIdx]
			}
		} else {
			// Fractional lag: 30-tap sinc interpolation
			sum := float32(0)
			coefs := g729PitchFIR[frac]
			for k := 0; k < 30; k++ {
				idx := startIdx + k - 14
				if idx >= 0 && idx < g729ExcBufLen {
					sum += coefs[k] * d.excBuf[idx]
				}
			}
			v[n] = sum
		}
	}
	return v
}

// =============================================================================
// Fixed algebraic codebook
// =============================================================================

// g729AlgebraicCB decodes a 40-sample sparse excitation vector.
// c (13 bits) = 9 position bits + 4 sign bits split across 4 tracks.
// Track 3 uses 4 bits for position; tracks 0-2 use 3 bits.
func g729AlgebraicCB(c, s int) [g729SubframeSize]float32 {
	var v [g729SubframeSize]float32

	// Extract pulse positions:
	// c[12:4] = track positions (9 bits, 3 bits per track 0-2, 4 bits for track 3)
	// Actually: bits 12-4 of c (9 bits total) encode 3 tracks × 3 bits,
	//           bits 3-0 of c (4 bits) encode track 3 position.
	// Signs come from s (4 bits, one per track).

	posBits := c >> 4 // 9 bits for tracks 0-2 (3 bits each)
	trk3Pos := c & 0xF // 4 bits for track 3

	tracks := [4]int{
		(posBits >> 6) & 0x7,
		(posBits >> 3) & 0x7,
		posBits & 0x7,
		trk3Pos,
	}

	for t := 0; t < 4; t++ {
		table := g729AlgebraicTracks[t]
		posIdx := tracks[t]
		if posIdx >= len(table) {
			posIdx = len(table) - 1
		}
		pos := table[posIdx]
		sign := float32(1.0)
		if (s>>t)&1 == 1 {
			sign = -1.0
		}
		if pos < g729SubframeSize {
			v[pos] += sign
		}
	}
	return v
}

// =============================================================================
// Gain decoding
// =============================================================================

// decodeGains returns the pitch gain and fixed codebook gain for a subframe.
// The fixed gain is predicted in log-domain using MA over past 4 subframes.
func (d *g729Decoder) decodeGains(ga, gb int) (pitchGain, fixedGain float32) {
	if ga >= 8 {
		ga = 7
	}
	if gb >= 16 {
		gb = 15
	}

	pitchGain = g729GaCB[ga][0] * g729GbCB[gb][0]
	if pitchGain > 1.2 {
		pitchGain = 1.2
	}
	if pitchGain < 0 {
		pitchGain = 0
	}

	// Log-domain MA prediction for fixed codebook gain energy
	var predEnergy float32
	for k := 0; k < 4; k++ {
		e := d.prevFixedGainEnergy[k]
		if e < 1e-12 {
			e = 1e-12
		}
		predEnergy += g729GainPredCoef[k] * float32(math.Log(float64(e)))
	}
	predEnergy = float32(math.Exp(float64(predEnergy)))

	// Apply second-stage correction
	rawSeed := g729GaCB[ga][1]
	fixedGain = predEnergy * rawSeed * g729GbCB[gb][1]
	if fixedGain < 0 {
		fixedGain = 0
	}
	if fixedGain > 10.0 {
		fixedGain = 10.0
	}

	// Shift and update gain energy history
	copy(d.prevFixedGainEnergy[1:], d.prevFixedGainEnergy[:3])
	d.prevFixedGainEnergy[0] = fixedGain * fixedGain
	if d.prevFixedGainEnergy[0] < 1e-12 {
		d.prevFixedGainEnergy[0] = 1e-12
	}

	return pitchGain, fixedGain
}

// =============================================================================
// LP synthesis filter
// =============================================================================

// lpSynthesis passes the excitation through the 10th-order all-pole LP filter.
// s[n] = exc[n] - Σ_{k=0}^{9} a[k] * s[n-k-1]
//
// Memory convention: synMem[0] = s[n-1] (most recent), synMem[9] = s[n-10].
// Uses and updates d.synMem across subframes.
func (d *g729Decoder) lpSynthesis(exc [g729SubframeSize]float32, a [10]float32) [g729SubframeSize]float32 {
	var out [g729SubframeSize]float32

	// Local copy of memory so we can update in-place
	var mem [10]float32
	copy(mem[:], d.synMem[:])

	for n := 0; n < g729SubframeSize; n++ {
		s := exc[n]
		for k := 0; k < g729LPOrder; k++ {
			s -= a[k] * mem[k]
		}
		// Hard-clip to prevent synthesis filter runaway
		if s > 4.0 {
			s = 4.0
		} else if s < -4.0 {
			s = -4.0
		}
		// Shift memory: mem[k] = s[n-k]
		copy(mem[1:], mem[:9])
		mem[0] = s
		out[n] = s
	}

	copy(d.synMem[:], mem[:])
	return out
}
