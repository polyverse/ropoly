package lib

type noEmptyStringsQueue struct {
	Items []string
	Index int
}

func (queue *noEmptyStringsQueue) dequeueString() string {
	ret := ""
	for ret == "" {
		ret = queue.Items[queue.Index]
		queue.Index++
	}
	return ret
}

type noEmptyByteArraysQueue struct {
	Items [][]byte
	Index int
}

func (queue *noEmptyByteArraysQueue) dequeueByteArray() []byte {
	ret := make([]byte, 0)
	for len(ret) == 0 {
		ret = queue.Items[queue.Index]
		queue.Index++
	}
	return ret
}
