package goproxy

import (
	"crypto/tls"
	"crypto/x509"
)

func init() {
	if goproxyCaErr != nil {
		panic("Error parsing builtin CA " + goproxyCaErr.Error())
	}
	var err error
	if GoproxyCa.Leaf, err = x509.ParseCertificate(GoproxyCa.Certificate[0]); err != nil {
		panic("Error parsing builtin CA " + err.Error())
	}
}

var tlsClientSkipVerify = &tls.Config{InsecureSkipVerify: true}

var defaultTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

var CA_CERT = []byte(`-----BEGIN CERTIFICATE-----
MIIDYDCCAkigAwIBAgIJAPKnGFfwxYC3MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTcxMjA1MjI0MzUxWhcNMTgwMzA1MjI0MzUxWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA8Xras1sxh2q28YagTq6AALg+pA0ATLDoh4L++DBG3Z/iv+ruPqpa6CD1
yJ5vK7lXy2krrQnvIAR9fMBZza3+Y+GnurHVypoxHAu5hULyzfZXmFxTV9P+8XAj
x6ZoY4dHZe3qxnD2ZcOi9gHTsLhJvTh4+vi47KiS/LNDnPmxk8+H/+tNrl8IHqa7
wyqyFCTxnkbPejUz5OCFnX0oMvCCeBffTALn/JGrWV8OomFfJdlN4hNqGDYwcuGV
whbDjzAvOW27aBTaBFlLkxAViTX1WjLUjBFxc5kv2F5RtqOIAkJVEovK346OyU/+
6icsHlqJzw0o9Ue30nJrH8V3oc8pIwIDAQABo1MwUTAdBgNVHQ4EFgQUDEyAyNII
mwfiVf/Qu1cn9pv80JkwHwYDVR0jBBgwFoAUDEyAyNIImwfiVf/Qu1cn9pv80Jkw
DwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAzEe4k5iRHd3nLjgK
3YSXwnT9PW+u4mCtP64FLEz/CYShg4c7Rn2kItSDVlhpYtvHbwygNJtZ+yXDFW2f
FH9HLgpBOLgG4uzJG3ds2DslrELM4N46n696xhKi+qpDzxTqGHSl8UKiOeQGiKqA
+svXgx0Y/bQbNl3eyUC61e2kWLkXC8HtaV3sn+1hF8iPw30HuqQtH6uv2wjIcvk7
wGrbaWPlguhB0N+IKoZRe/Sj20czFpl6MS3B1oDkfvBG+3iZgoC8GkBU37ZFfJAN
dXqSXYmLZvVXqLPAom05Y3gUOqyZgLc3QNjiT29GL1ts0zN+1R3dImK+1/eRhlK/
0wrS9w==
-----END CERTIFICATE-----`)

var CA_KEY = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA8Xras1sxh2q28YagTq6AALg+pA0ATLDoh4L++DBG3Z/iv+ru
Pqpa6CD1yJ5vK7lXy2krrQnvIAR9fMBZza3+Y+GnurHVypoxHAu5hULyzfZXmFxT
V9P+8XAjx6ZoY4dHZe3qxnD2ZcOi9gHTsLhJvTh4+vi47KiS/LNDnPmxk8+H/+tN
rl8IHqa7wyqyFCTxnkbPejUz5OCFnX0oMvCCeBffTALn/JGrWV8OomFfJdlN4hNq
GDYwcuGVwhbDjzAvOW27aBTaBFlLkxAViTX1WjLUjBFxc5kv2F5RtqOIAkJVEovK
346OyU/+6icsHlqJzw0o9Ue30nJrH8V3oc8pIwIDAQABAoIBAE45jAs56WuCqEzJ
XbjfUlvpU3F1PLmbPVhYmRvxF6PHnX6qLg9ixBwaQUSB/mVdnxEnupxNcYcfrT7y
WKUGTjgw61LRNP5ywKHjMm/25gzOVkXm8qCq7hVsTErqnzpOolRko/8wrMD+hRXI
Nbkzmb+QQbCbTdxsJ2Fw+OArCtlkagW2/lFLu6FVrPYyR7cXlEeKKXdyOgJaxi7q
217uR4JaqdbAqrCLv6/poJm+UqhH59HIl7T7Ssqa6vxpGp4JHK3FM9VnTkNiULjd
kd4vwAGC861xc3JKgbKB3/V8R+VaqlSCVmVVt6M0wwfa7hOtk3f9mVzVBhgA8G5/
f7QsNuECgYEA+MW7oRiGtvaIRQ7HJvlfTJwC4gIbvjBTrVfepZ+GN2qBsRu6VH55
xrRikLRrFAfIaYa8I2txEYFtIwlQUYi2p9AmDWJ10+ZmlZhwibpdijtHMKHpOGDy
vz3hAKqOKUxeZX5uyw/SP3/93WJoW3bMt0UKBfeecnp/9rJ/+mebq+kCgYEA+H7h
/lZ9UCexeenpx1TzR/oPb/IiXY6tZWIWrkEDI+diLqdj7mwlJ5KeF66MPzh3lIis
8fUoGVltDJhccIpZRrH4Mg3hJ/4nt+Tj9Ol5lruet6ldoYag5KQwjBGadDoj5b+1
W7+sI8S+8XU/jSsXXvPS71n/9axeG2TztOSWYSsCgYEA5hTTDRKG/c8Th3M8g/Jd
zpf4Hpm+mO9PZOIA/QOGedharLgtZBo5fKq3AoirBDKSi+7eMJAdWghvLNlfXJlp
/dkIaJaozVupgzAi3W7tNnzOwc7tyYP43yFW6WvU4aNNJueBhvNSDALPg6KRTA6b
FeGXfJ9g/xYHJd4/eRO8KYkCgYEAyi8am8EtZqlVKreawdeptheMte3R7kNna8T6
ZT96WZ0q8oC5u0T8mg0eWnBnpgzApvbpmFh7Dt0G8CeLlvnKF843/iny14JgOKyg
mSXaCz2Oryq7hvAuOroo0d6EyCqCCK4J1qPGYLf1ECrw0WCNPHGwX5TfwLlFPI7Q
B4+xl08CgYBOPY5G6Zc9n1pwiqsKkEXsAyDr0QYngggkqbywfN7s/ARxJhXzvG1X
kFmQHBL9i/O1hIAEBLbPtVKXkBRTEZAY31uYkfzAyNCXg5zVOm0AzFzUC8A/MU6N
C2dWRdoR9BvPjDWUU7mDHCL11+s5oxI9anY9HmJd53515vtGlduodQ==
-----END RSA PRIVATE KEY-----`)

var GoproxyCa, goproxyCaErr = tls.X509KeyPair(CA_CERT, CA_KEY)
