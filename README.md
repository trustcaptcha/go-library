# Trustcaptcha Go-Library

The Go library helps you to integrate Trustcaptcha into your Go backend applications.


## What is Trustcaptcha?

A captcha solution that protects you from bot attacks and puts a special focus on user experience and data protection.

You can find more information on your website: [www.trustcaptcha.com](https://www.trustcaptcha.com).


## How does the library work?

Detailed instructions and examples for using the library can be found in our [documentation](https://docs.trustcaptcha.com/en/documentation/backend/integration?backend=go).


## Short example

Here you can see a short code example of a possible integration. Please refer to our provided [documentation](https://docs.trustcaptcha.com/en/documentation/backend/integration?backend=go) for complete and up-to-date integration instructions.

Installing the library

``go get github.com/trustcaptcha/go-library@v1.0.1``

Fetching and handling the result

```
// Retrieving the verification result
verificationResult, err := trustcaptcha.GetVerificationResult("<your_secret_key>", "<verification_token_from_your_client>")

// Do something with the verification result
if !verificationResult.VerificationPassed || verificationResult.Score > 0.5 {
  log.Println("Verification failed, or bot score is higher than 0.5 – this could indicate a bot.")
}
```

## Ideas and support

If you have any ideas, suggestions, or need support, please [contact us](https://www.trustcaptcha.com/en/contact-us).
