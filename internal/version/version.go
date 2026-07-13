package version

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

const (
	GlobalConfigSchema  = 2
	ProjectConfigSchema = 1
	// ConfigSchema is retained for version output and means the global schema.
	ConfigSchema     = GlobalConfigSchema
	ProtocolVersion  = 3
	ProviderProtocol = 1
	MutagenVersion   = "0.18.1"
)
