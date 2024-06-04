package trustcaptcha

type VerificationToken struct {
	ApiEndpoint          string `json:"apiEndpoint"`
	VerificationId       string `json:"verificationId"`
	EncryptedAccessToken string `json:"encryptedAccessToken"`
}

type VerificationResult struct {
	CaptchaId          string  `json:"captchaId"`
	VerificationId     string  `json:"verificationId"`
	Score              float64 `json:"score"`
	Reason             string  `json:"reason"`
	Mode               string  `json:"mode"`
	Origin             string  `json:"origin"`
	IpAddress          string  `json:"ipAddress"`
	DeviceFamily       string  `json:"deviceFamily"`
	OperatingSystem    string  `json:"operatingSystem"`
	Browser            string  `json:"browser"`
	CreationTimestamp  string  `json:"creationTimestamp"`
	ReleaseTimestamp   string  `json:"releaseTimestamp"`
	RetrievalTimestamp string  `json:"retrievalTimestamp"`
	VerificationPassed bool    `json:"verificationPassed"`
}
