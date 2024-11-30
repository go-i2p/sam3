package common

type ProtocolVersion string

type Version struct {
	String ProtocolVersion
	Number float64
}

var (
	SAM31Version = Version{
		String: "3.1",
		Number: 3.1,
	}
	SAM33Version = Version{
		String: "3.3",
		Number: 3.3,
	}
)
