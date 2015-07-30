// +build linux

package seccomp

import (
	"fmt"
	"syscall"
	"unsafe"
)

type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

func newFilter() *filter {
	var f filter
	f = append(f, sockFilter{
		pfLD + syscall.BPF_W + syscall.BPF_ABS,
		0,
		0,
		uint32(unsafe.Offsetof(secData.nr)),
	})
	return &f
}

// this checks for a value inside a mask. The evalusation is equal to doing
// CLONE_NEWUSER & syscallMask == CLONE_NEWUSER
func jumpMaskEqualTo(f *filter, v uint, jt sockFilter) {
        lo := uint32(uint64(v) % 0x100000000)
        hi := uint32(uint64(v) / 0x100000000)
        *f = append(*f, scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, hi, 0, 6))
        *f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_MEM, 0))
        *f = append(*f, scmpBpfStmt(syscall.BPF_ALU+syscall.BPF_AND, uint32(v)))
        *f = append(*f, scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, lo, 0, 2))
        *f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_MEM, 1))
        *f = append(*f, jt)
        *f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_MEM, 1))
}

func jumpGreaterThan(f *filter, v uint, jt sockFilter) {
	lo := uint32(uint64(v) % 0x100000000)
	hi := uint32(uint64(v) / 0x100000000)
	*f = append(*f, scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JGT+syscall.BPF_K, (hi), 4, 0))
	*f = append(*f, scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, (hi), 0, 5))
	*f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_MEM, 0))
	*f = append(*f, scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JGE+syscall.BPF_K, (lo), 0, 2))
	*f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_MEM, 1))
	*f = append(*f, jt)
	*f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_MEM, 1))
}

func jumpEqualTo(f *filter, v uint, jt sockFilter) {
	lo := uint32(uint64(v) % 0x100000000)
	hi := uint32(uint64(v) / 0x100000000)
	*f = append(*f, scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, (hi), 0, 5))
	*f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_MEM, 0))
	*f = append(*f, scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, (lo), 0, 2))
	*f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_MEM, 1))
	*f = append(*f, jt)
	*f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_MEM, 1))
}

func jumpLessThan(f *filter, v uint, jt sockFilter) {
	lo := uint32(uint64(v) % 0x100000000)
	hi := uint32(uint64(v) / 0x100000000)
	*f = append(*f, scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JGT+syscall.BPF_K, (hi), 6, 0))
	*f = append(*f, scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, (hi), 0, 3))
	*f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_MEM, 0))
	*f = append(*f, scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JGT+syscall.BPF_K, (lo), 2, 0))
	*f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_MEM, 1))
	*f = append(*f, jt)
	*f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_MEM, 1))
}

func jumpNotEqualTo(f *filter, v uint, jt sockFilter) {
	lo := uint32(uint64(v) % 0x100000000)
	hi := uint32(uint64(v) / 0x100000000)
	*f = append(*f, scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, hi, 5, 0))
	*f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_MEM, 0))
	*f = append(*f, scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, lo, 2, 0))
	*f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_MEM, 1))
	*f = append(*f, jt)
	*f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_MEM, 1))
}

// this checks for a value inside a mask. The evalusation is equal to doing
// CLONE_NEWUSER & syscallMask == CLONE_NEWUSER
type filter []sockFilter

func (f *filter) addSyscall(s *Syscall, labels *bpfLabels) {
	if len(s.Args) == 0 {
		f.call(s.Value, scmpBpfStmt(syscall.BPF_RET+syscall.BPF_K, s.scmpAction()))
	} else {
		if len(s.Args[0]) > 0 {
			lb := fmt.Sprintf(labelTemplate, s.Value, s.Args[0][0].Index)
			f.call(s.Value,
				scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JA, labelIndex(labels, lb),
					jumpJT, jumpJF))
		}
	}
}

func (f *filter) addArguments(s *Syscall, labels *bpfLabels) error {
	for i := 0; len(s.Args) > i; i++ {
		if len(s.Args[i]) > 0 {
			lb := fmt.Sprintf(labelTemplate, s.Value, s.Args[i][0].Index)
			f.label(labels, lb)
			f.arg(s.Args[i][0].Index)
		}
		for j := 0; j < len(s.Args[i]); j++ {
			var jf sockFilter
			if len(s.Args)-1 > i && len(s.Args[i+1]) > 0 {
				lbj := fmt.Sprintf(labelTemplate, s.Value, s.Args[i+1][0].Index)
				jf = scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JA,
					labelIndex(labels, lbj), jumpJT, jumpJF)
			} else {
				jf = scmpBpfStmt(syscall.BPF_RET+syscall.BPF_K, s.scmpAction())
			}
			if err := f.op(s.Args[i][j].Op, s.Args[i][j].Value, jf); err != nil {
				return err
			}
		}
		f.allow()
	}
	return nil
}

func (f *filter) label(labels *bpfLabels, lb string) {
	*f = append(*f, scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JA, labelIndex(labels, lb), labelJT, labelJF))
}

func (f *filter) call(nr uint32, jt sockFilter) {
	*f = append(*f, scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, nr, 0, 1))
	*f = append(*f, jt)
}

func (f *filter) allow() {
	*f = append(*f, scmpBpfStmt(syscall.BPF_RET+syscall.BPF_K, retAllow))
}

func (f *filter) deny() {
	*f = append(*f, scmpBpfStmt(syscall.BPF_RET+syscall.BPF_K, retTrap))
}

func (f *filter) arg(index uint32) {
	arg(f, index)
}

func (f *filter) op(operation Operator, v uint, jf sockFilter) error {
	switch operation {
	case EqualTo:
		jumpEqualTo(f, v, jf)
	case NotEqualTo:
		jumpNotEqualTo(f, v, jf)
	case GreatherThan:
		jumpGreaterThan(f, v, jf)
	case LessThan:
		jumpLessThan(f, v, jf)
	case MaskEqualTo:
		jumpMaskEqualTo(f, v, jf)
	default:
		return ErrUnsupportedOperation
	}
	return nil
}

func arg(f *filter, idx uint32) {
	*f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_W+syscall.BPF_ABS, endian.low(idx)))
	*f = append(*f, scmpBpfStmt(syscall.BPF_ST, 0))
	*f = append(*f, scmpBpfStmt(syscall.BPF_LD+syscall.BPF_W+syscall.BPF_ABS, endian.hi(idx)))
	*f = append(*f, scmpBpfStmt(syscall.BPF_ST, 1))
}

func jump(f *filter, labels *bpfLabels, lb string) {
	*f = append(*f, scmpBpfJump(syscall.BPF_JMP+syscall.BPF_JA, labelIndex(labels, lb),
		jumpJT, jumpJF))
}
