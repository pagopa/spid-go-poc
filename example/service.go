package main

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"

	"github.com/f-lombardo/spid-go/spidsaml"
)

// This demo application shows how to use the spidsaml package

// This is a stateless object representing your Service Provider. It does
// not hold any information about active sessions, so you can safely store
// it in a global variable.
var sp *spidsaml.SP

// IMPORTANT:
// These variables belong the session of each user. In an actual application
// you would NOT store them as global variables, but you'd store them in the
// user session backed by a cookie, using for example github.com/gorilla/sessions,
// but for simplicity in this example application we are doing this way.
var spidSession *spidsaml.Session
var authnReqID, logoutReqID string

func main() {
	// Initialize our SPID object with information about this Service Provider
	// lettura di variabile d'ambiente per il base path
	base_path := os.Getenv("BASE_PATH") // qualcosa tipo v2
	assertionConsumerService := "http://localhost:8000/spid-sso"
	singleLogoutService := "http://localhost:8000/spid-slo"

	if base_path != "" {
		base_path = "/" + base_path
		assertionConsumerService = "http://localhost:8000" + base_path + "/spid-sso"
		singleLogoutService = "http://localhost:8000" + base_path + "/spid-slo"
	}

	sp = &spidsaml.SP{
		EntityID: "http://localhost:8000" + base_path,
		KeyFile:  "key.pem",
		CertFile: "crt.pem",
		AssertionConsumerServices: []string{
			assertionConsumerService,
		},
		SingleLogoutServices: map[string]spidsaml.SAMLBinding{
			singleLogoutService: spidsaml.HTTPRedirect,
		},
		AttributeConsumingServices: []spidsaml.AttributeConsumingService{
			{
				ServiceName: "Service 1",
				Attributes:  []string{"fiscalNumber", "name", "familyName", "dateOfBirth"},
			},
		},
		Organization: spidsaml.Organization{
			Names:        []string{"Foobar"},
			DisplayNames: []string{"Foobar"},
			URLs:         []string{"https://www.foobar.it/"},
		},
	}

	// Load Identity Providers from their XML metadata
	err := sp.LoadIDPMetadata("idp_metadata")
	if err != nil {
		// fmt.Print("Failed to load IdP metadata: ")
		// fmt.Println(err)
		return
	}

	http.HandleFunc(base_path+"/", index)
	http.HandleFunc(base_path+"/metadata", metadata)
	http.HandleFunc(base_path+"/spid-login", spidLogin)
	http.HandleFunc(base_path+"/spid-sso", spidSSO)
	http.HandleFunc(base_path+"/logout", spidLogout)
	http.HandleFunc(base_path+"/spid-slo", spidSLO)

	// Dance
	fmt.Println("spid-go example application listening on http://localhost:8000" + base_path)
	http.ListenAndServe(":8000", nil)
}

const tmplLayout = `<!DOCTYPE html>
<html lang="en-US">
<head>
    <title>spid-go Example Application</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
    <meta charset="UTF-8" />
</head>
<body>
    <div class="container">
        <h1>spid-go Example Application</h1>
        <div id="content">
        {{ . }}
        </div>
    </div>
</body>
</html>
`

const tmplUser = `<p>This page shows details about the currently logged user.</p>
<p><a class="btn btn-primary" href="/logout">Logout</a></p>
<h1>NameID:</h1>
<p>{{ .NameID }}</p>
<h2>SPID Level:</h2>
<p>{{ .Level }}</p>
<h2>Attributes</h2>
<table>
  <tr>
    <th>Key</th>
    <th>Value</th>
  </tr>
  {{ range $key, $val := .Attributes }}
      <tr>
        <td>{{ $key }}</td>
        <td>{{ $val }}</td>
	  </tr>
  {{ end }}
</table>
`
const tmplUser_2 = `<p>This page shows details about the currently logged user.</p>
<p><a class="btn btn-primary" href="/v1/logout">Logout</a></p>
<h1>NameID:</h1>
<p>{{ .NameID }}</p>
<h2>SPID Level:</h2>
<p>{{ .Level }}</p>
<h2>Attributes</h2>
<table>
  <tr>
    <th>Key</th>
    <th>Value</th>
  </tr>
  {{ range $key, $val := .Attributes }}
      <tr>
        <td>{{ $key }}</td>
        <td>{{ $val }}</td>
	  </tr>
  {{ end }}
</table>
`

// If we have an active SPID session, display a page with user attributes,
// otherwise show a generic login page containing the SPID button.
func index(w http.ResponseWriter, r *http.Request) {
	// lettura di variabile d'ambiente per il base path
	base_path := os.Getenv("BASE_PATH") // qualcosa tipo v1

	if base_path != "" {
		base_path = "/" + base_path
	}
	t := template.Must(template.New("index").Parse(tmplLayout))
	if spidSession == nil {
		button := sp.GetButton(base_path + "/spid-login?idp=%s")
		t.Execute(w, template.HTML(button))
	} else {
		var t2 bytes.Buffer
		tmpToUse := tmplUser

		if base_path != "" {
			tmpToUse = tmplUser_2
		}

		template.Must(template.New("user").Parse(tmpToUse)).Execute(&t2, spidSession)
		t.Execute(w, template.HTML(t2.String()))
	}
}

// This endpoint exposes our metadata
func metadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml")
	// RedirectURL
	spMetadata, err := sp.Metadata()
	if err != nil {
		http.Error(w, "Error creating Metadata", http.StatusBadRequest)
		return
	}
	io.WriteString(w, spMetadata)
}

// This endpoint initiates SSO through the user-chosen Identity Provider.
func spidLogin(w http.ResponseWriter, r *http.Request) {
	// Check that we have the mandatory 'idp' parameter and that it matches
	// an available Identity Provider.
	idp, err := sp.GetIDP(r.URL.Query().Get("idp"))
	if err != nil {
		http.Error(w, "Invalid IdP selected", http.StatusBadRequest)
		return
	}

	spNewAuthnRequest, err := sp.NewAuthnRequest(idp)
	if err != nil {
		http.Error(w, "Error creating AuthnRequest", http.StatusBadRequest)
		return
	}

	base_path := os.Getenv("BASE_PATH") // qualcosa tipo v1
	if base_path != "" {
		base_path = "/" + base_path
	}

	// Craft the AuthnRequest.
	authnreq := spNewAuthnRequest
	authnreq.AcsURL = "http://localhost:8000" + base_path + "/spid-sso"
	authnreq.AcsIndex = 0
	authnreq.AttrIndex = 0
	authnreq.Level = 2
	authnreq.RelayState = authnreq.ID

	// Save the ID of the Authnreq so that we can check it in the response
	// in order to prevent forgery.
	authnReqID = authnreq.ID

	// Uncomment the following lines to use the HTTP-POST binding instead of HTTP-Redirect:
	postForm, err := authnreq.PostForm()
	if err != nil {
		http.Error(w, "Error during HTTP-POST binding", http.StatusBadRequest)
		return
	}
	w.Write(postForm)
	return

	// // Redirect user to the IdP using its HTTP-Redirect binding.
	// redirectURL, err := authnreq.RedirectURL()
	// if err != nil {
	// 	http.Error(w, "Error creating HTTP-Redirect binding", http.StatusBadRequest)
	// 	return
	// }
	// http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// This endpoint exposes an AssertionConsumerService for our Service Provider.
// During SSO, the Identity Provider will redirect user to this URL POSTing
// the resulting assertion.
func spidSSO(w http.ResponseWriter, r *http.Request) {
	// Parse and verify the incoming assertion.
	r.ParseForm()
	response, err := sp.ParseResponse(
		r,
		authnReqID, // Match the ID of our authentication request for increased security.
	)

	// Clear the ID of the outgoing Authnreq, regardless of the result.
	authnReqID = ""

	// TODO: better error handling:
	// - authentication failure
	// - authentication cancelled by user
	// - temporary server error
	// - unavailable SPID level

	// In case of SSO failure, display an error page.
	if err != nil {
		// fmt.Printf("Bad Response received: %s\n", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Log response as required by the SPID rules.
	// Hint: log it in a way that does not mangle whitespace preventing signature from
	// being verified at a later time
	// fmt.Printf("SPID Response: %s\n", response.XML)

	if response.Success() {
		// Login successful! Initialize our application session and store
		// the SPID information for later retrieval.
		// TODO: this should be stored in a database instead of the current Dancer
		// session, and it should be indexed by SPID SessionID so that we can delete
		// it when we get a LogoutRequest from an IdP.
		spidSession = response.Session()

		// TODO: handle SPID level upgrade:
		// - does session ID remain the same? better assume it changes

		base_path := os.Getenv("BASE_PATH") // qualcosa tipo v1
		if base_path != "" {
			base_path = "/" + base_path
		}

		http.Redirect(w, r, base_path+"/", http.StatusSeeOther)
	} else {
		fmt.Fprintf(w, "Authentication Failed: %s (%s)",
			response.StatusMessage(), response.StatusCode2())
	}
}

// This endpoint initiates logout.
func spidLogout(w http.ResponseWriter, r *http.Request) {
	// If we don't have an open SPID session, do nothing.
	if spidSession == nil {
		base_path := os.Getenv("BASE_PATH") // qualcosa tipo v1
		if base_path != "" {
			base_path = "/" + base_path
		}
		http.Redirect(w, r, base_path+"/", http.StatusSeeOther)
		return
	}

	// Craft the LogoutRequest.
	logoutreq, err := sp.NewLogoutRequest(spidSession)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Save the ID of the LogoutRequest so that we can check it in the response
	// in order to prevent forgery.
	logoutReqID = logoutreq.ID

	// Uncomment the following line to use the HTTP-POST binding instead of HTTP-Redirect:
	logutreqPostForm, err := logoutreq.PostForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write(logutreqPostForm)
	return

	// Redirect user to the Identity Provider for logout.
	// http.Redirect(w, r, logoutreq.RedirectURL(), http.StatusSeeOther)
}

// This endpoint exposes a SingleLogoutService for our Service Provider, using
// a HTTP-POST or HTTP-Redirect binding (this package does not support SOAP).
// Identity Providers can direct both LogoutRequest and LogoutResponse messages
// to this endpoint.
func spidSLO(w http.ResponseWriter, r *http.Request) {
	base_path := os.Getenv("BASE_PATH") // qualcosa tipo v1
	if base_path != "" {
		base_path = "/" + base_path
	}

	if spidSession == nil {
		http.Redirect(w, r, base_path+"/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	if (r.Form.Get("SAMLResponse") != "" || r.URL.Query().Get("SAMLResponse") != "") && logoutReqID != "" {
		// This is the response to a SP-initiated logout.

		// Parse the response and catch validation errors.
		_, err := sp.ParseLogoutResponse(
			r,
			logoutReqID, // Match the ID of our logout request for increased security.
		)

		// In case of SLO failure, display an error page.
		if err != nil {
			// fmt.Printf("Bad LogoutResponse received: %s\n", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Logout was successful! Clear the local session.
		logoutReqID = ""
		spidSession = nil
		fmt.Println("Session successfully destroyed.")

		// TODO: handle partial logout. Log? Show message to user?
		// if (logoutres.Status() == logoutres.Partial) { ... }

		// Redirect user back to main page.
		http.Redirect(w, r, base_path+"/", http.StatusSeeOther)
	} else if r.Form.Get("SAMLRequest") != "" || r.URL.Query().Get("SAMLRequest") != "" {
		// This is a LogoutRequest (IdP-initiated logout).

		logoutreq, err := sp.ParseLogoutRequest(r)

		if err != nil {
			// fmt.Printf("Bad LogoutRequest received: %s\n", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Now we should retrieve the local session corresponding to the SPID
		// session logoutreq.SessionIndex(). However, since we are implementing a HTTP-POST
		// binding, this HTTP request comes from the user agent so the current user
		// session is automatically the right one. This simplifies things a lot as
		// retrieving another session by SPID session ID is tricky without a more
		// complex architecture.
		status := spidsaml.SuccessLogout
		if logoutreq.SessionIndex() == spidSession.SessionIndex {
			spidSession = nil
		} else {
			status = spidsaml.PartialLogout
			fmt.Printf("SAML LogoutRequest session (%s) does not match current SPID session (%s)\n",
				logoutreq.SessionIndex(), spidSession.SessionIndex)
		}

		// Craft a LogoutResponse and send it back to the Identity Provider.
		logoutres, err := sp.NewLogoutResponse(logoutreq, status)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Redirect user to the Identity Provider for logout.
		logoutresRedirectURL, err := logoutres.RedirectURL()
		if err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, logoutresRedirectURL, http.StatusSeeOther)
	} else {
		http.Error(w, "Invalid request", http.StatusBadRequest)
	}
}
