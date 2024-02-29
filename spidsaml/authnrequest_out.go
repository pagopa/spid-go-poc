package spidsaml

import (
	"bytes"
	"text/template"
)

// AuthnRequest defines an outgoing SPID/SAML AuthnRequest.
// Do not instantiate it directly but use sp.NewAuthnRequest() instead.
type AuthnRequest struct {
	outMessage
	AcsURL     string
	AcsIndex   int
	AttrIndex  int
	Level      int
	Comparison string
}

// NewAuthnRequest generates an AuthnRequest addressed to this Identity Provider.
// Note that this method does not perform any network call, it just initializes
// an object.
func (sp *SP) NewAuthnRequest(idp *IDP) (*AuthnRequest, error) {
	reqID, err := generateMessageID()
	if err != nil {
		return nil, err
	}

	req := new(AuthnRequest)
	req.ID = reqID
	req.SP = sp
	req.IDP = idp
	req.AcsIndex = -1
	req.AttrIndex = -1
	req.Level = 1
	req.Comparison = "minimum"
	return req, err
}

// XML generates the XML representation of this AuthnRequest
func (authnreq *AuthnRequest) XML(binding SAMLBinding) ([]byte, error) {
	var signatureTemplate string
	if binding == HTTPPost {
		signatureTemplateByte, err := authnreq.signatureTemplate()
		if err != nil {
			return nil, err
		}
		signatureTemplate = string(signatureTemplateByte)
	}

	data := struct {
		*AuthnRequest
		Destination       string
		IssueInstant      string
		SignatureTemplate string
	}{
		authnreq,
		authnreq.IDP.SSOURLs[binding],
		authnreq.IssueInstantString(),
		signatureTemplate,
	}

	const tmpl = `<?xml version="1.0"?> 
	<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{{ .ID }}"
    Version="2.0"
    IssueInstant="{{ .IssueInstant }}"
	Destination="{{ .Destination }}"
	
	{{ if ne .AcsURL "" }}
    AssertionConsumerServiceURL="{{ .AcsURL }}"
	ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	{{ else if ne .AcsIndex -1 }}
	AssertionConsumerServiceIndex="{{ .AcsIndex }}"
	{{ end }}
	
	{{ if ne .AttrIndex -1 }}
	AttributeConsumingServiceIndex="{{ .AttrIndex }}"
	{{ end }}

	ForceAuthn="{{ if gt .Level 1 }}true{{ else }}false{{ end }}">
	
	<saml:Issuer NameQualifier="{{.SP.EntityID}}" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{{.SP.EntityID}}</saml:Issuer>

	{{ .SignatureTemplate }}

    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" />
    <samlp:RequestedAuthnContext Comparison="{{ .Comparison }}"><saml:AuthnContextClassRef>https://www.spid.gov.it/SpidL{{.Level}}</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
`

	t := template.Must(template.New("req").Parse(tmpl))
	var metadata bytes.Buffer
	t.Execute(&metadata, data)
	return metadata.Bytes(), nil
}

// RedirectURL returns the full URL of the Identity Provider where user should be
// redirected in order to initiate their Single Sign-On. In SAML words, this
// implements the HTTP-Redirect binding.
func (authnreq *AuthnRequest) RedirectURL() (string, error) {
	authnreqXML, err := authnreq.XML(HTTPRedirect)
	if err != nil {
		return "", err
	}
	return authnreq.outMessage.RedirectURL(
		authnreq.IDP.SSOURLs[HTTPRedirect],
		authnreqXML,
		"SAMLRequest",
	)
}

// PostForm returns an HTML page with a JavaScript auto-post command that submits
// the request to the Identity Provider in order to initiate their Single Sign-On.
// In SAML words, this implements the HTTP-POST binding.
func (authnreq *AuthnRequest) PostForm() ([]byte, error) {
	authnreqXML, err := authnreq.XML(HTTPPost)
	if err != nil {
		return nil, err
	}
	return authnreq.outMessage.PostForm(
		authnreq.IDP.SSOURLs[HTTPPost],
		authnreqXML,
		"SAMLRequest",
	)
}
