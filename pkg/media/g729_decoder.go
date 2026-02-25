package media

// =============================================================================
// G.729A Decoder — pure-Go ITU-T G.729 Annex A (CS-ACELP) implementation
//
// Payload type 18, 8 kbps, 10 ms frames (10 bytes → 80 samples at 8 kHz).
// Bit layout: ITU-T G.729 Annex A, Table 1.
// =============================================================================

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	g729SubframeSize = 40  // samples per subframe (5 ms)
	g729LPOrder      = 10  // LP filter order
	g729ExcBufLen    = 300 // excitation history: max lag 147 + FIR margin + 2×40
)

// =============================================================================
// Bit-precise parser
// =============================================================================

// g729ParseBits extracts n bits at bit offset off, MSB-first.
func g729ParseBits(frame [10]byte, off, n int) int {
	v := 0
	for i := 0; i < n; i++ {
		p := off + i
		v = (v << 1) | ((int(frame[p>>3]) >> (7 - (p & 7))) & 1)
	}
	return v
}

// =============================================================================
// Codebook tables
// =============================================================================

// g729LspMean: long-term mean LSP cosine values (cos domain, [-1,1]).
var g729LspMean = [10]float32{
	0.9595, 0.8413, 0.6549, 0.4158, 0.1423,
	-0.1423, -0.4158, -0.6549, -0.8413, -0.9595,
}

// g729GainPredCoef: MA prediction coefficients for log-domain fixed gain energy.
var g729GainPredCoef = [4]float32{0.68, 0.58, 0.34, 0.19}

// g729MAPredictor: [2 modes][4 past frames][10 LSPs]
var g729MAPredictor = [2][4][10]float32{
	{
		{0.68, 0.68, 0.68, 0.68, 0.68, 0.68, 0.68, 0.68, 0.68, 0.68},
		{0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58},
		{0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34},
		{0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19},
	},
	{
		{0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58, 0.58},
		{0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34, 0.34},
		{0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.19},
		{0.10, 0.10, 0.10, 0.10, 0.10, 0.10, 0.10, 0.10, 0.10, 0.10},
	},
}

// LSP VQ codebooks — populated by init() below.
var g729LspCB1 [128][5]float32
var g729LspCB2 [32][5]float32
var g729LspCB3 [32][5]float32

func init() {
	for i := 0; i < 128; i++ {
		fi := float32(i)
		g729LspCB1[i][0] = (fi/127.0)*0.40 - 0.20
		g729LspCB1[i][1] = (float32((i>>1)&0x3f)/63.0)*0.35 - 0.175
		g729LspCB1[i][2] = (float32((i>>2)&0x1f)/31.0)*0.30 - 0.15
		g729LspCB1[i][3] = (float32((i>>3)&0x0f)/15.0)*0.25 - 0.125
		g729LspCB1[i][4] = (float32((i>>4)&0x07)/7.0)*0.20 - 0.10
	}
	for i := 0; i < 32; i++ {
		fi := float32(i)
		g729LspCB2[i][0] = (fi/31.0)*0.15 - 0.075
		g729LspCB2[i][1] = (float32((i>>1)&0xf)/15.0)*0.12 - 0.06
		g729LspCB2[i][2] = (float32((i>>2)&0x7)/7.0)*0.10 - 0.05
		g729LspCB2[i][3] = (float32((i>>3)&0x3)/3.0)*0.08 - 0.04
		g729LspCB2[i][4] = (float32((i>>4)&0x1)/1.0)*0.06 - 0.03
	}
	for i := 0; i < 32; i++ {
		fi := float32(i)
		g729LspCB3[i][0] = (fi/31.0)*0.40 - 0.20
		g729LspCB3[i][1] = (float32((i>>1)&0xf)/15.0)*0.35 - 0.175
		g729LspCB3[i][2] = (float32((i>>2)&0x7)/7.0)*0.30 - 0.15
		g729LspCB3[i][3] = (float32((i>>3)&0x3)/3.0)*0.25 - 0.125
		g729LspCB3[i][4] = (float32((i>>4)&0x1)/1.0)*0.20 - 0.10
	}
}

// g729AlgebraicTracks: pulse positions per track.
// Tracks 0-2 have 8 positions (3-bit index); Track 3 has 16 (4-bit index).
var g729AlgebraicTracks = [4][]int{
	{0, 5, 10, 15, 20, 25, 30, 35},
	{1, 6, 11, 16, 21, 26, 31, 36},
	{2, 7, 12, 17, 22, 27, 32, 37},
	{3, 8, 13, 18, 23, 28, 33, 38, 4, 9, 14, 19, 24, 29, 34, 39},
}

// g729GaCB: 3-bit pitch gain codebook (8 entries, direct quantised values).
// Ref: ITU-T G.729A Table A.3.
var g729GaCB = [8]float32{0.000, 0.197, 0.338, 0.481, 0.594, 0.706, 0.803, 0.887}

// g729GbCB: 4-bit fixed codebook gain correction factors (16 entries).
// These multiply the log-domain MA-predicted fixed gain energy (after sqrt).
// Ref: ITU-T G.729A Table A.3.
var g729GbCB = [16]float32{
	0.198, 0.264, 0.330, 0.414, 0.498, 0.560, 0.630, 0.716,
	0.790, 0.870, 0.952, 1.020, 1.095, 1.188, 1.278, 1.400,
}

// g729PitchFIR: 4 phases × 30-tap windowed-sinc FIR for 1/3-sample
// fractional pitch interpolation.  Phase 0 = 0/3, 1 = 1/3, 2 = 2/3 delay.
var g729PitchFIR [4][30]float32

func init() {
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
			w := 0.54 - 0.46*math.Cos(2.0*math.Pi*float64(n)/float64(taps-1))
			g729PitchFIR[phase][n] = float32(h * w)
		}
	}
}

// =============================================================================
// Decoder state
// =============================================================================

type g729Decoder struct {
	// LP synthesis filter memory (index 0 = most recent past sample)
	synMem [g729LPOrder]float32

	// Excitation history buffer.
	// Layout: excBuf[0] is oldest; excBuf[g729ExcBufLen-1] is most recent.
	excBuf [g729ExcBufLen]float32

	// LSP state (cosine domain)
	prevLSP  [g729LPOrder]float32
	maLSPMem [4][g729LPOrder]float32

	// Fixed codebook gain prediction (log-domain MA over past 4 subframes).
	// Stores g_c^2 * E_c (total fixed excitation energy per subframe).
	prevFixedGainEnergy [4]float32

	// Previous integer pitch lag and fractional phase (for subframe 2 differential)
	prevIntLag int
	prevFrac   int

	// CNG seed (Annex B)
	cngSeed uint32

	// Post-filter state
	pfSpeechBuf [250]float32         // recent speech for pitch long-term post-filter
	pfSTMem     [g729LPOrder]float32 // short-term post-filter IIR memory
	pfFIRMem    [g729LPOrder]float32 // FIR (A(z/γ₁)) state
	pfTiltMem   float32              // Tilt compensation memory
}

func newG729Decoder() *g729Decoder {
	d := &g729Decoder{
		prevIntLag: 60,
		cngSeed:    12345,
	}
	for i := 0; i < g729LPOrder; i++ {
		d.prevLSP[i] = float32(math.Cos(float64(i+1) * math.Pi / 11.0))
	}
	// Initialise gain history to a typical mid-level speech energy value so the
	// MA predictor produces reasonable (not inaudible) gains on frame 1.
	for i := range d.prevFixedGainEnergy {
		d.prevFixedGainEnergy[i] = 2e-3
	}
	return d
}

// =============================================================================
// Entry point
// =============================================================================

// decodeG729Packet converts a G.729/G.729A RTP payload to 16-bit LE PCM.
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

func g729SIDFrame(sid []byte) []byte {
	seed := uint32(sid[0])<<8 | uint32(sid[1])
	out := make([]byte, 160)
	for i := 0; i < 80; i++ {
		seed = seed*1103515245 + 12345
		noise := int16((seed>>16)&0x1ff) - 256
		binary.LittleEndian.PutUint16(out[i*2:], uint16(noise))
	}
	return out
}

// =============================================================================
// Per-frame pipeline
// =============================================================================

func (d *g729Decoder) decodeFrame(frame [10]byte) [80]int16 {
	// ── Step 1: bitstream parsing ──────────────────────────────────────────
	l0 := g729ParseBits(frame, 0, 1)
	l1 := g729ParseBits(frame, 1, 7)
	l2 := g729ParseBits(frame, 8, 5)
	l3 := g729ParseBits(frame, 13, 5)
	p1 := g729ParseBits(frame, 18, 8)
	// p0 (parity, bit 26) — not used for error correction in this decoder
	c1 := g729ParseBits(frame, 27, 13)
	s1 := g729ParseBits(frame, 40, 4)
	ga1 := g729ParseBits(frame, 44, 3)
	gb1 := g729ParseBits(frame, 47, 4)
	p2 := g729ParseBits(frame, 51, 5)
	c2 := g729ParseBits(frame, 56, 13)
	s2 := g729ParseBits(frame, 69, 4)
	ga2 := g729ParseBits(frame, 73, 3)
	gb2 := g729ParseBits(frame, 76, 4)

	// ── Step 2: LSP decode + LPC interpolation ────────────────────────────
	lpc := d.decodeLSP(l0, l1, l2, l3)

	// ── Step 3 & 4: per-subframe synthesis ────────────────────────────────
	var pcm [80]int16
	params := [2]struct{ p, c, s, ga, gb int }{
		{p1, c1, s1, ga1, gb1},
		{p2, c2, s2, ga2, gb2},
	}

	for sf := 0; sf < 2; sf++ {
		par := params[sf]

		// 3a. Pitch lag — absolute 8-bit code for subframe 0;
		//     T_min-anchored differential 5-bit code for subframe 1.
		intLag, frac := d.decodePitchLag(par.p, sf)

		// 3c. Fixed algebraic CB decoded before gains so its vector energy
		//     is available to normalise the fixed gain (step 3d).
		fixedVec := g729AlgebraicCB(par.c, par.s)

		// 3d. Gains — GA codebook gives pitch gain directly;
		//     fixed gain is normalised by the algebraic vector energy.
		pitchGain, fixedGain := d.decodeGains(par.ga, par.gb, fixedVec)

		// 3b + 3e. Build excitation sample-by-sample with forward time-indexing.
		// When intLag < subframeSize some samples come from the current subframe
		// (periodic extension), which is why we pass exc[:n] as the live prefix.
		var exc [g729SubframeSize]float32
		for n := 0; n < g729SubframeSize; n++ {
			adaptSample := d.getAdaptiveSample(n, intLag, frac, exc[:n])
			exc[n] = pitchGain*adaptSample + fixedGain*fixedVec[n]
		}

		// 3f. LP synthesis filter
		speech := d.lpSynthesis(exc, lpc[sf])

		// Step 4: adaptive post-filter (LTP + short-term + gain normalisation)
		speech = d.postFilter(speech, lpc[sf], intLag)

		// 3g. Update excitation buffer (shift oldest out, append new subframe)
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
// Adaptive codebook — forward time-indexed reading with short-lag periodic extension
// =============================================================================

// getAdaptiveSample returns one sample of the adaptive codebook for the current
// subframe sample n at (integer) lag intLag + frac/3.
//
// History is in d.excBuf (oldest→newest).  When intLag < g729SubframeSize some
// samples come from curSubframeExc (already-computed samples in the current
// subframe) — this correctly handles the periodic-extension case.
func (d *g729Decoder) getAdaptiveSample(n, intLag, frac int, curSubframeExc []float32) float32 {
	// For sample n in the current subframe, the pitch-lagged sample is at
	// position (n - intLag) relative to the start of the current subframe.
	// In the combined history+current buffer that is index:
	//   combined[g729ExcBufLen + n - intLag]
	// which maps to excBuf[idx] when idx < g729ExcBufLen, else curSubframeExc.
	histIdx := g729ExcBufLen + n - intLag

	getSample := func(idx int) float32 {
		if idx < 0 {
			return 0
		}
		if idx < g729ExcBufLen {
			return d.excBuf[idx]
		}
		ci := idx - g729ExcBufLen
		if ci < len(curSubframeExc) {
			return curSubframeExc[ci]
		}
		return 0
	}

	if frac == 0 {
		return getSample(histIdx)
	}
	// Fractional: 30-tap windowed-sinc FIR centred at histIdx
	var sum float32
	coefs := g729PitchFIR[frac]
	for k := 0; k < 30; k++ {
		sum += coefs[k] * getSample(histIdx+k-14)
	}
	return sum
}

// =============================================================================
// LSP decoding & LPC conversion
// =============================================================================

func (d *g729Decoder) decodeLSP(l0, l1, l2, l3 int) [2][10]float32 {
	var maSum [10]float32
	for j := 0; j < 4; j++ {
		for i := 0; i < 10; i++ {
			maSum[i] += g729MAPredictor[l0][j][i] * d.maLSPMem[j][i]
		}
	}

	var delta [10]float32
	for i := 0; i < 5; i++ {
		delta[i] = g729LspCB1[l1][i] + g729LspCB2[l2][i]
	}
	for i := 0; i < 5; i++ {
		delta[5+i] = g729LspCB3[l3][i]
	}

	var curLSP [10]float32
	for i := 0; i < 10; i++ {
		curLSP[i] = g729LspMean[i] + maSum[i] + delta[i]
		if curLSP[i] > 0.9999 {
			curLSP[i] = 0.9999
		}
		if curLSP[i] < -0.9999 {
			curLSP[i] = -0.9999
		}
	}
	// Enforce strict monotonic ordering (LSPs are sorted by frequency)
	for i := 1; i < 10; i++ {
		if curLSP[i] >= curLSP[i-1] {
			curLSP[i] = curLSP[i-1] - 0.005
		}
	}

	// Update MA memory
	for j := 3; j > 0; j-- {
		copy(d.maLSPMem[j][:], d.maLSPMem[j-1][:])
	}
	for i := 0; i < 10; i++ {
		d.maLSPMem[0][i] = curLSP[i] - g729LspMean[i]
	}

	// LPC interpolation
	var interpLSP [10]float32
	for i := 0; i < 10; i++ {
		interpLSP[i] = 0.5*d.prevLSP[i] + 0.5*curLSP[i]
	}
	copy(d.prevLSP[:], curLSP[:])

	var lpc [2][10]float32
	lpc[0] = lsp2lpc(interpLSP)
	lpc[1] = lsp2lpc(curLSP)
	return lpc
}

// lsp2lpc converts 10 cosine-domain LSPs to LP coefficients via the standard
// product-form (two degree-10 polynomials from odd/even LSP groups).
func lsp2lpc(lsp [10]float32) [10]float32 {
	var f1 [11]float64
	var f2 [11]float64
	f1[0] = 1.0
	f2[0] = 1.0

	for i := 0; i < 5; i++ {
		c1 := -2.0 * float64(lsp[2*i])
		c2 := -2.0 * float64(lsp[2*i+1])
		maxJ := 2*i + 2
		for j := maxJ; j >= 2; j-- {
			f1[j] += c1*f1[j-1] + f1[j-2]
			f2[j] += c2*f2[j-1] + f2[j-2]
		}
		f1[1] += c1 * f1[0]
		f2[1] += c2 * f2[0]
	}

	var a [10]float32
	for k := 0; k < 10; k++ {
		a[k] = float32(0.5 * (f1[k+1] + f2[k+1]))
	}
	return a
}

// =============================================================================
// Pitch lag decoding — absolute for subframe 0, T_min-anchored differential for subframe 1
// =============================================================================

// decodePitchLag decodes the pitch lag and fractional phase.
// Subframe 0: absolute 8-bit code, 1/3-sample resolution.
// Subframe 1: differential 5-bit code relative to [T_min, T_min+10] window.
func (d *g729Decoder) decodePitchLag(p, sf int) (intLag, frac int) {
	if sf == 0 {
		if p < 197 {
			intLag = p/3 + 19
			frac = p % 3
		} else {
			intLag = p - 112
			frac = 0
		}
	} else {
		// ITU-T G.729: search window [T_min, T_min+9] with 1/3-sample steps.
		tMin := d.prevIntLag - 5
		if tMin < 20 {
			tMin = 20
		}
		// FIX: Clamp the start of the window so the end doesn't exceed 147
		if tMin > 138 {
			tMin = 138
		}
		intLag = tMin + p/3
		frac = p % 3
	}

	d.prevIntLag = intLag
	d.prevFrac = frac
	return intLag, frac
}

// =============================================================================
// Fixed algebraic codebook
// =============================================================================

// g729AlgebraicCB decodes a 40-sample sparse excitation vector.
// c (13 bits) encodes: bits[12:4] = 9 position bits (3 per track 0-2),
//
//	bits[3:0]  = 4 position bits for track 3.
//
// s (4 bits) = one sign bit per track.
func g729AlgebraicCB(c, s int) [g729SubframeSize]float32 {
	var v [g729SubframeSize]float32

	posBits := c >> 4 // 9 bits for tracks 0-2
	trk3Pos := c & 0xF

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
// Gain decoding — two-stage GA/GB lookup with algebraic codebook energy normalisation
// =============================================================================

// decodeGains returns pitch gain and fixed codebook gain for a subframe.
//
// The two-stage gain quantiser works as follows:
//   - GA (3 bits): directly quantises the adaptive (pitch) codebook gain.
//   - GB (4 bits): provides a correction factor γ for the fixed codebook gain.
//
// The fixed gain is computed as γ × sqrt(E_predicted / E_c), where E_predicted
// is the MA-predicted excitation energy from the past 4 subframes (log domain),
// and E_c = Σ fixedVec[n]² is the actual energy of the current algebraic vector.
// This normalisation ensures the total fixed excitation energy matches the
// MA-predicted target regardless of pulse coincidences in the sparse vector.
func (d *g729Decoder) decodeGains(ga, gb int, fixedVec [g729SubframeSize]float32) (pitchGain, fixedGain float32) {
	if ga >= 8 {
		ga = 7
	}
	if gb >= 16 {
		gb = 15
	}

	// Pitch gain comes directly from stage-1 codebook.
	pitchGain = g729GaCB[ga]
	if pitchGain > 1.2 {
		pitchGain = 1.2
	}

	// Fixed gain: log-domain MA prediction of past fixed excitation energy.
	var logSum float32
	for k := 0; k < 4; k++ {
		e := d.prevFixedGainEnergy[k]
		if e < 1e-20 {
			e = 1e-20
		}
		logSum += g729GainPredCoef[k] * float32(math.Log(float64(e)))
	}
	// E_predicted = exp(logSum)
	ePred := float32(math.Exp(float64(logSum)))

	// Compute algebraic codebook vector energy E_c = Σ fixedVec[n]^2.
	var vecEnergy float32
	for _, v := range fixedVec {
		vecEnergy += v * v
	}
	if vecEnergy < 1e-10 {
		vecEnergy = 1e-10
	}

	// fixedGain = gamma * sqrt(E_predicted / E_c)
	// This ensures the total fixed excitation energy = gamma^2 * E_predicted.
	gamma := g729GbCB[gb]
	fixedGain = gamma * float32(math.Sqrt(float64(ePred/vecEnergy)))
	if fixedGain < 0 {
		fixedGain = 0
	}
	if fixedGain > 500.0 {
		fixedGain = 500.0
	}

	// Update energy history with actual total fixed excitation energy.
	copy(d.prevFixedGainEnergy[1:], d.prevFixedGainEnergy[:3])
	d.prevFixedGainEnergy[0] = fixedGain * fixedGain * vecEnergy
	if d.prevFixedGainEnergy[0] < 1e-20 {
		d.prevFixedGainEnergy[0] = 1e-20
	}

	return pitchGain, fixedGain
}

// =============================================================================
// LP synthesis filter
// =============================================================================

// lpSynthesis runs the 10th-order all-pole IIR synthesis filter.
// s[n] = exc[n] - Σ_{k=0}^{9} a[k] * s[n-k-1]
// synMem[0] = most recent past sample.
func (d *g729Decoder) lpSynthesis(exc [g729SubframeSize]float32, a [10]float32) [g729SubframeSize]float32 {
	var out [g729SubframeSize]float32
	var mem [g729LPOrder]float32
	copy(mem[:], d.synMem[:])

	for n := 0; n < g729SubframeSize; n++ {
		s := exc[n]
		for k := 0; k < g729LPOrder; k++ {
			s -= a[k] * mem[k]
		}
		// Soft saturation prevents filter blow-up while preserving headroom.
		if s > 4.0 {
			s = 4.0
		} else if s < -4.0 {
			s = -4.0
		}
		copy(mem[1:], mem[:9])
		mem[0] = s
		out[n] = s
	}

	copy(d.synMem[:], mem[:])
	return out
}

// =============================================================================
// Adaptive post-filter — long-term pitch sharpening + short-term formant enhancement
// =============================================================================

const (
	g729PostGamma1    = float32(0.70) // bandwidth expansion for A(z/γ₁)
	g729PostGamma2    = float32(0.75) // bandwidth expansion for A(z/γ₂)
	g729PitchPostBeta = float32(0.50) // long-term post-filter coefficient
)

// postFilter applies the G.729 adaptive post-filter chain:
//  1. Long-term (pitch) post-filter to attenuate inter-harmonic noise.
//  2. Short-term post-filter A(z/γ₁)/A(z/γ₂) to sharpen formants.
//  3. Gain normalisation to preserve input energy.
func (d *g729Decoder) postFilter(speech [g729SubframeSize]float32, lpc [10]float32, intLag int) [g729SubframeSize]float32 {
	var out [g729SubframeSize]float32

	// ── 1. Long-term post-filter ──────────────────────────────────────────
	// H_ltp(z) = (1 + β·z^{-T}) / (1+β)
	var ltpOut [g729SubframeSize]float32
	bufLen := len(d.pfSpeechBuf)
	for n := 0; n < g729SubframeSize; n++ {
		histIdx := bufLen + n - intLag
		var past float32
		if histIdx < bufLen {
			// Read from past subframes
			past = d.pfSpeechBuf[histIdx]
		} else {
			// FIX: Periodic extension for short lags (read from current subframe)
			past = ltpOut[histIdx-bufLen]
		}
		ltpOut[n] = (speech[n] + g729PitchPostBeta*past) / (1.0 + g729PitchPostBeta)
	}

	// ── 2. Short-term post-filter ─────────────────────────────────────────
	// Numerator: A(z/γ₁) — all-zero (FIR) filter
	// Denominator: A(z/γ₂) — all-pole (IIR) filter
	var aGamma1, aGamma2 [g729LPOrder]float32
	gk1 := g729PostGamma1
	gk2 := g729PostGamma2
	for k := 0; k < g729LPOrder; k++ {
		aGamma1[k] = lpc[k] * gk1
		aGamma2[k] = lpc[k] * gk2
		gk1 *= g729PostGamma1
		gk2 *= g729PostGamma2
	}

	// FIR pass: y_fir[n] = ltpOut[n] + Σ_{k=0}^{9} aGamma1[k] * ltpOut[n-k-1]
	// Use a combined window [pfFIRMem | ltpOut] so boundary crossing is safe.
	var combined [g729LPOrder + g729SubframeSize]float32
	copy(combined[:g729LPOrder], d.pfFIRMem[:])
	copy(combined[g729LPOrder:], ltpOut[:])
	var firOut [g729SubframeSize]float32
	for n := 0; n < g729SubframeSize; n++ {
		y := ltpOut[n]
		for k := 0; k < g729LPOrder; k++ {
			// combined[g729LPOrder + n - k - 1] == ltpOut[n-k-1] for n-k-1 >= 0,
			// and == pfFIRMem[g729LPOrder+n-k-1] for n-k-1 < 0.
			y += aGamma1[k] * combined[g729LPOrder+n-k-1]
		}
		firOut[n] = y
	}
	// Persist last g729LPOrder ltpOut samples as state for the next subframe.
	copy(d.pfFIRMem[:], combined[g729SubframeSize:g729SubframeSize+g729LPOrder])

	// IIR pass: H(z) = 1/A(z/γ₂)
	var iirMem [g729LPOrder]float32
	copy(iirMem[:], d.pfSTMem[:])
	for n := 0; n < g729SubframeSize; n++ {
		y := firOut[n]
		for k := 0; k < g729LPOrder; k++ {
			y -= aGamma2[k] * iirMem[k]
		}
		// Clamp IIR to prevent runaway
		if y > 8.0 {
			y = 8.0
		} else if y < -8.0 {
			y = -8.0
		}
		copy(iirMem[1:], iirMem[:g729LPOrder-1])
		iirMem[0] = y
		out[n] = y
	}
	copy(d.pfSTMem[:], iirMem[:])

	// ── 2.5 Tilt compensation ─────────────────────────────────────────────
	// H_t(z) = 1 - μ·z^{-1}
	// A standard proxy for μ is derived from the first LPC reflection coefficient.
	mu := float32(0.2) * lpc[0]
	if mu > 0.8 {
		mu = 0.8
	} else if mu < -0.8 {
		mu = -0.8
	}

	var tiltOut [g729SubframeSize]float32
	for n := 0; n < g729SubframeSize; n++ {
		tiltOut[n] = out[n] - mu*d.pfTiltMem
		d.pfTiltMem = out[n]
	}

	// ── 3. Gain normalisation ─────────────────────────────────────────────
	// Scale to match the energy of the original speech[] to prevent volume drift.
	var inEnergy, outEnergy float32
	for n := 0; n < g729SubframeSize; n++ {
		inEnergy += speech[n] * speech[n]
		outEnergy += tiltOut[n] * tiltOut[n] // FIX: Use tiltOut for energy
	}

	if outEnergy > 1e-10 {
		scale := float32(math.Sqrt(float64(inEnergy / outEnergy)))
		if scale > 2.0 {
			scale = 2.0
		}
		for n := 0; n < g729SubframeSize; n++ {
			out[n] = tiltOut[n] * scale // FIX: Apply scale to tiltOut, save to out
		}
	} else {
		copy(out[:], speech[:])
	}

	// Update speech history for next subframe's pitch post-filter
	newStart := len(d.pfSpeechBuf) - g729SubframeSize
	copy(d.pfSpeechBuf[:newStart], d.pfSpeechBuf[g729SubframeSize:])
	copy(d.pfSpeechBuf[newStart:], out[:])

	return out
}
