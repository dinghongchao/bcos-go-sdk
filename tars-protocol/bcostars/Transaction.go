// Package bcostars comment
// This file was generated by tars2go 1.1.10
// Generated from Transaction.tars
package bcostars

import (
	"fmt"

	"github.com/TarsCloud/TarsGo/tars/protocol/codec"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = fmt.Errorf
var _ = codec.FromInt8

// TransactionData struct implement
type TransactionData struct {
	Version    int32  `json:"version"`
	ChainID    string `json:"chainID"`
	GroupID    string `json:"groupID"`
	BlockLimit int64  `json:"blockLimit"`
	Nonce      string `json:"nonce"`
	To         string `json:"to"`
	Input      []int8 `json:"input"`
}

func (st *TransactionData) ResetDefault() {
}

// ReadFrom reads  from readBuf and put into struct.
func (st *TransactionData) ReadFrom(readBuf *codec.Reader) error {
	var (
		err    error
		length int32
		have   bool
		ty     byte
	)
	st.ResetDefault()

	err = readBuf.ReadInt32(&st.Version, 1, true)
	if err != nil {
		return err
	}

	err = readBuf.ReadString(&st.ChainID, 2, true)
	if err != nil {
		return err
	}

	err = readBuf.ReadString(&st.GroupID, 3, true)
	if err != nil {
		return err
	}

	err = readBuf.ReadInt64(&st.BlockLimit, 4, true)
	if err != nil {
		return err
	}

	err = readBuf.ReadString(&st.Nonce, 5, true)
	if err != nil {
		return err
	}

	err = readBuf.ReadString(&st.To, 6, false)
	if err != nil {
		return err
	}

	_, ty, err = readBuf.SkipToNoCheck(7, true)
	if err != nil {
		return err
	}

	if ty == codec.LIST {
		err = readBuf.ReadInt32(&length, 0, true)
		if err != nil {
			return err
		}

		st.Input = make([]int8, length)
		for i0, e0 := int32(0), length; i0 < e0; i0++ {

			err = readBuf.ReadInt8(&st.Input[i0], 0, false)
			if err != nil {
				return err
			}

		}
	} else if ty == codec.SimpleList {

		_, err = readBuf.SkipTo(codec.BYTE, 0, true)
		if err != nil {
			return err
		}

		err = readBuf.ReadInt32(&length, 0, true)
		if err != nil {
			return err
		}

		err = readBuf.ReadSliceInt8(&st.Input, length, true)
		if err != nil {
			return err
		}

	} else {
		err = fmt.Errorf("require vector, but not")
		if err != nil {
			return err
		}

	}

	_ = err
	_ = length
	_ = have
	_ = ty
	return nil
}

// ReadBlock reads struct from the given tag , require or optional.
func (st *TransactionData) ReadBlock(readBuf *codec.Reader, tag byte, require bool) error {
	var (
		err  error
		have bool
	)
	st.ResetDefault()

	have, err = readBuf.SkipTo(codec.StructBegin, tag, require)
	if err != nil {
		return err
	}
	if !have {
		if require {
			return fmt.Errorf("require TransactionData, but not exist. tag %d", tag)
		}
		return nil
	}

	err = st.ReadFrom(readBuf)
	if err != nil {
		return err
	}

	err = readBuf.SkipToStructEnd()
	if err != nil {
		return err
	}
	_ = have
	return nil
}

// WriteTo encode struct to buffer
func (st *TransactionData) WriteTo(buf *codec.Buffer) (err error) {

	err = buf.WriteInt32(st.Version, 1)
	if err != nil {
		return err
	}

	err = buf.WriteString(st.ChainID, 2)
	if err != nil {
		return err
	}

	err = buf.WriteString(st.GroupID, 3)
	if err != nil {
		return err
	}

	err = buf.WriteInt64(st.BlockLimit, 4)
	if err != nil {
		return err
	}

	err = buf.WriteString(st.Nonce, 5)
	if err != nil {
		return err
	}

	err = buf.WriteString(st.To, 6)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.SimpleList, 7)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.BYTE, 0)
	if err != nil {
		return err
	}

	err = buf.WriteInt32(int32(len(st.Input)), 0)
	if err != nil {
		return err
	}

	err = buf.WriteSliceInt8(st.Input)
	if err != nil {
		return err
	}

	return err
}

// WriteBlock encode struct
func (st *TransactionData) WriteBlock(buf *codec.Buffer, tag byte) error {
	var err error
	err = buf.WriteHead(codec.StructBegin, tag)
	if err != nil {
		return err
	}

	err = st.WriteTo(buf)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.StructEnd, 0)
	if err != nil {
		return err
	}
	return nil
}

// Transaction struct implement
type Transaction struct {
	Data       TransactionData `json:"data"`
	DataHash   []int8          `json:"dataHash"`
	Signature  []int8          `json:"signature"`
	ImportTime int64           `json:"importTime"`
	Attribute  int32           `json:"attribute"`
	Source     string          `json:"source"`
	Sender     []int8          `json:"sender"`
}

func (st *Transaction) ResetDefault() {
	st.Data.ResetDefault()
}

// ReadFrom reads  from readBuf and put into struct.
func (st *Transaction) ReadFrom(readBuf *codec.Reader) error {
	var (
		err    error
		length int32
		have   bool
		ty     byte
	)
	st.ResetDefault()

	err = st.Data.ReadBlock(readBuf, 1, false)
	if err != nil {
		return err
	}

	have, ty, err = readBuf.SkipToNoCheck(2, false)
	if err != nil {
		return err
	}

	if have {
		if ty == codec.LIST {
			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}

			st.DataHash = make([]int8, length)
			for i0, e0 := int32(0), length; i0 < e0; i0++ {

				err = readBuf.ReadInt8(&st.DataHash[i0], 0, false)
				if err != nil {
					return err
				}

			}
		} else if ty == codec.SimpleList {

			_, err = readBuf.SkipTo(codec.BYTE, 0, true)
			if err != nil {
				return err
			}

			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}

			err = readBuf.ReadSliceInt8(&st.DataHash, length, true)
			if err != nil {
				return err
			}

		} else {
			err = fmt.Errorf("require vector, but not")
			if err != nil {
				return err
			}

		}
	}

	have, ty, err = readBuf.SkipToNoCheck(3, false)
	if err != nil {
		return err
	}

	if have {
		if ty == codec.LIST {
			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}

			st.Signature = make([]int8, length)
			for i1, e1 := int32(0), length; i1 < e1; i1++ {

				err = readBuf.ReadInt8(&st.Signature[i1], 0, false)
				if err != nil {
					return err
				}

			}
		} else if ty == codec.SimpleList {

			_, err = readBuf.SkipTo(codec.BYTE, 0, true)
			if err != nil {
				return err
			}

			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}

			err = readBuf.ReadSliceInt8(&st.Signature, length, true)
			if err != nil {
				return err
			}

		} else {
			err = fmt.Errorf("require vector, but not")
			if err != nil {
				return err
			}

		}
	}

	err = readBuf.ReadInt64(&st.ImportTime, 4, false)
	if err != nil {
		return err
	}

	err = readBuf.ReadInt32(&st.Attribute, 5, false)
	if err != nil {
		return err
	}

	err = readBuf.ReadString(&st.Source, 6, false)
	if err != nil {
		return err
	}

	have, ty, err = readBuf.SkipToNoCheck(7, false)
	if err != nil {
		return err
	}

	if have {
		if ty == codec.LIST {
			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}

			st.Sender = make([]int8, length)
			for i2, e2 := int32(0), length; i2 < e2; i2++ {

				err = readBuf.ReadInt8(&st.Sender[i2], 0, false)
				if err != nil {
					return err
				}

			}
		} else if ty == codec.SimpleList {

			_, err = readBuf.SkipTo(codec.BYTE, 0, true)
			if err != nil {
				return err
			}

			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}

			err = readBuf.ReadSliceInt8(&st.Sender, length, true)
			if err != nil {
				return err
			}

		} else {
			err = fmt.Errorf("require vector, but not")
			if err != nil {
				return err
			}

		}
	}

	_ = err
	_ = length
	_ = have
	_ = ty
	return nil
}

// ReadBlock reads struct from the given tag , require or optional.
func (st *Transaction) ReadBlock(readBuf *codec.Reader, tag byte, require bool) error {
	var (
		err  error
		have bool
	)
	st.ResetDefault()

	have, err = readBuf.SkipTo(codec.StructBegin, tag, require)
	if err != nil {
		return err
	}
	if !have {
		if require {
			return fmt.Errorf("require Transaction, but not exist. tag %d", tag)
		}
		return nil
	}

	err = st.ReadFrom(readBuf)
	if err != nil {
		return err
	}

	err = readBuf.SkipToStructEnd()
	if err != nil {
		return err
	}
	_ = have
	return nil
}

// WriteTo encode struct to buffer
func (st *Transaction) WriteTo(buf *codec.Buffer) (err error) {

	err = st.Data.WriteBlock(buf, 1)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.SimpleList, 2)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.BYTE, 0)
	if err != nil {
		return err
	}

	err = buf.WriteInt32(int32(len(st.DataHash)), 0)
	if err != nil {
		return err
	}

	err = buf.WriteSliceInt8(st.DataHash)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.SimpleList, 3)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.BYTE, 0)
	if err != nil {
		return err
	}

	err = buf.WriteInt32(int32(len(st.Signature)), 0)
	if err != nil {
		return err
	}

	err = buf.WriteSliceInt8(st.Signature)
	if err != nil {
		return err
	}

	err = buf.WriteInt64(st.ImportTime, 4)
	if err != nil {
		return err
	}

	err = buf.WriteInt32(st.Attribute, 5)
	if err != nil {
		return err
	}

	err = buf.WriteString(st.Source, 6)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.SimpleList, 7)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.BYTE, 0)
	if err != nil {
		return err
	}

	err = buf.WriteInt32(int32(len(st.Sender)), 0)
	if err != nil {
		return err
	}

	err = buf.WriteSliceInt8(st.Sender)
	if err != nil {
		return err
	}

	return err
}

// WriteBlock encode struct
func (st *Transaction) WriteBlock(buf *codec.Buffer, tag byte) error {
	var err error
	err = buf.WriteHead(codec.StructBegin, tag)
	if err != nil {
		return err
	}

	err = st.WriteTo(buf)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.StructEnd, 0)
	if err != nil {
		return err
	}
	return nil
}
