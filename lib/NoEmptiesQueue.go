package lib

type noEmptyStringsQueue struct {
	Items []string
	Index int
}

func dequeueString(queue *noEmptyStringsQueue) string {
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

func dequeueByteArray(queue *noEmptyByteArraysQueue) []byte {
	ret := make([]byte, 0)
	for len(ret) == 0 {
		ret = queue.Items[queue.Index]
		queue.Index++
	}
	return ret
}
