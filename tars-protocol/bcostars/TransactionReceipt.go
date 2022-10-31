// Package bcostars comment
// This file was generated by tars2go 1.1.10
// Generated from TransactionReceipt.tars
package bcostars

import (
	"fmt"

	"github.com/TarsCloud/TarsGo/tars/protocol/codec"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = fmt.Errorf
var _ = codec.FromInt8

// LogEntry struct implement
type LogEntry struct {
	Address string   `json:"address"`
	Topic   [][]int8 `json:"topic"`
	Data    []int8   `json:"data"`
}

func (st *LogEntry) ResetDefault() {
}

// ReadFrom reads  from readBuf and put into struct.
func (st *LogEntry) ReadFrom(readBuf *codec.Reader) error {
	var (
		err    error
		length int32
		have   bool
		ty     byte
	)
	st.ResetDefault()

	err = readBuf.ReadString(&st.Address, 1, false)
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

			st.Topic = make([][]int8, length)
			for i0, e0 := int32(0), length; i0 < e0; i0++ {

				have, ty, err = readBuf.SkipToNoCheck(0, false)
				if err != nil {
					return err
				}

				if have {
					if ty == codec.LIST {
						err = readBuf.ReadInt32(&length, 0, true)
						if err != nil {
							return err
						}

						st.Topic[i0] = make([]int8, length)
						for i1, e1 := int32(0), length; i1 < e1; i1++ {

							err = readBuf.ReadInt8(&st.Topic[i0][i1], 0, false)
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

						err = readBuf.ReadSliceInt8(&st.Topic[i0], length, true)
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
			}
		} else if ty == codec.SimpleList {
			err = fmt.Errorf("not support SimpleList type")
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

			st.Data = make([]int8, length)
			for i2, e2 := int32(0), length; i2 < e2; i2++ {

				err = readBuf.ReadInt8(&st.Data[i2], 0, false)
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

			err = readBuf.ReadSliceInt8(&st.Data, length, true)
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
func (st *LogEntry) ReadBlock(readBuf *codec.Reader, tag byte, require bool) error {
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
			return fmt.Errorf("require LogEntry, but not exist. tag %d", tag)
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
func (st *LogEntry) WriteTo(buf *codec.Buffer) (err error) {

	err = buf.WriteString(st.Address, 1)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.LIST, 2)
	if err != nil {
		return err
	}

	err = buf.WriteInt32(int32(len(st.Topic)), 0)
	if err != nil {
		return err
	}

	for _, v := range st.Topic {

		err = buf.WriteHead(codec.SimpleList, 0)
		if err != nil {
			return err
		}

		err = buf.WriteHead(codec.BYTE, 0)
		if err != nil {
			return err
		}

		err = buf.WriteInt32(int32(len(v)), 0)
		if err != nil {
			return err
		}

		err = buf.WriteSliceInt8(v)
		if err != nil {
			return err
		}

	}

	err = buf.WriteHead(codec.SimpleList, 3)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.BYTE, 0)
	if err != nil {
		return err
	}

	err = buf.WriteInt32(int32(len(st.Data)), 0)
	if err != nil {
		return err
	}

	err = buf.WriteSliceInt8(st.Data)
	if err != nil {
		return err
	}

	return err
}

// WriteBlock encode struct
func (st *LogEntry) WriteBlock(buf *codec.Buffer, tag byte) error {
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

// TransactionReceiptData struct implement
type TransactionReceiptData struct {
	Version         int32      `json:"version"`
	GasUsed         string     `json:"gasUsed"`
	ContractAddress string     `json:"contractAddress"`
	Status          int32      `json:"status"`
	Output          []int8     `json:"output"`
	LogEntries      []LogEntry `json:"logEntries"`
	BlockNumber     int64      `json:"blockNumber"`
}

func (st *TransactionReceiptData) ResetDefault() {
}

// ReadFrom reads  from readBuf and put into struct.
func (st *TransactionReceiptData) ReadFrom(readBuf *codec.Reader) error {
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

	err = readBuf.ReadString(&st.GasUsed, 2, true)
	if err != nil {
		return err
	}

	err = readBuf.ReadString(&st.ContractAddress, 3, false)
	if err != nil {
		return err
	}

	err = readBuf.ReadInt32(&st.Status, 4, true)
	if err != nil {
		return err
	}

	have, ty, err = readBuf.SkipToNoCheck(5, false)
	if err != nil {
		return err
	}

	if have {
		if ty == codec.LIST {
			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}

			st.Output = make([]int8, length)
			for i0, e0 := int32(0), length; i0 < e0; i0++ {

				err = readBuf.ReadInt8(&st.Output[i0], 0, false)
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

			err = readBuf.ReadSliceInt8(&st.Output, length, true)
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

	have, ty, err = readBuf.SkipToNoCheck(6, false)
	if err != nil {
		return err
	}

	if have {
		if ty == codec.LIST {
			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}

			st.LogEntries = make([]LogEntry, length)
			for i1, e1 := int32(0), length; i1 < e1; i1++ {

				err = st.LogEntries[i1].ReadBlock(readBuf, 0, false)
				if err != nil {
					return err
				}

			}
		} else if ty == codec.SimpleList {
			err = fmt.Errorf("not support SimpleList type")
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

	err = readBuf.ReadInt64(&st.BlockNumber, 7, true)
	if err != nil {
		return err
	}

	_ = err
	_ = length
	_ = have
	_ = ty
	return nil
}

// ReadBlock reads struct from the given tag , require or optional.
func (st *TransactionReceiptData) ReadBlock(readBuf *codec.Reader, tag byte, require bool) error {
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
			return fmt.Errorf("require TransactionReceiptData, but not exist. tag %d", tag)
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
func (st *TransactionReceiptData) WriteTo(buf *codec.Buffer) (err error) {

	err = buf.WriteInt32(st.Version, 1)
	if err != nil {
		return err
	}

	err = buf.WriteString(st.GasUsed, 2)
	if err != nil {
		return err
	}

	err = buf.WriteString(st.ContractAddress, 3)
	if err != nil {
		return err
	}

	err = buf.WriteInt32(st.Status, 4)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.SimpleList, 5)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.BYTE, 0)
	if err != nil {
		return err
	}

	err = buf.WriteInt32(int32(len(st.Output)), 0)
	if err != nil {
		return err
	}

	err = buf.WriteSliceInt8(st.Output)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.LIST, 6)
	if err != nil {
		return err
	}

	err = buf.WriteInt32(int32(len(st.LogEntries)), 0)
	if err != nil {
		return err
	}

	for _, v := range st.LogEntries {

		err = v.WriteBlock(buf, 0)
		if err != nil {
			return err
		}

	}

	err = buf.WriteInt64(st.BlockNumber, 7)
	if err != nil {
		return err
	}

	return err
}

// WriteBlock encode struct
func (st *TransactionReceiptData) WriteBlock(buf *codec.Buffer, tag byte) error {
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

// TransactionReceipt struct implement
type TransactionReceipt struct {
	Data     TransactionReceiptData `json:"data"`
	DataHash []int8                 `json:"dataHash"`
}

func (st *TransactionReceipt) ResetDefault() {
	st.Data.ResetDefault()
}

// ReadFrom reads  from readBuf and put into struct.
func (st *TransactionReceipt) ReadFrom(readBuf *codec.Reader) error {
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

	_ = err
	_ = length
	_ = have
	_ = ty
	return nil
}

// ReadBlock reads struct from the given tag , require or optional.
func (st *TransactionReceipt) ReadBlock(readBuf *codec.Reader, tag byte, require bool) error {
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
			return fmt.Errorf("require TransactionReceipt, but not exist. tag %d", tag)
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
func (st *TransactionReceipt) WriteTo(buf *codec.Buffer) (err error) {

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

	return err
}

// WriteBlock encode struct
func (st *TransactionReceipt) WriteBlock(buf *codec.Buffer, tag byte) error {
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
