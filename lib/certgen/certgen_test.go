package certgen

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/Cloud-Foundations/Dominator/lib/x509util"
	"github.com/Cloud-Foundations/golib/pkg/log/testlogger"
	"golang.org/x/crypto/ssh"
)

/*
func TestMissingGroup(t *testing.T) {

        val1 := strings.NewReader(user1Data)
        val2 := strings.NewReader(user1MissingEngineeringGroup)
        r, err := getDiff(val1, val2)
        if err != nil {
                t.Fatal(err)
        }
        if r == "" {
                t.Errorf("expecting data, got empty")
        }
        t.Log("got '%s'", r)

}
*/

const testSignerPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAv2J464KoYbODMIbtkTV58g6/0QTdUIYgOwnzPdaMNVtCOxTi
QDIWEbzqv1HEP9hfzuaSKHUHs/91e4Jj2qZghSwPHLG7TKzu+/CRK9sa9jvoGEVx
g6yjibPndTGuLVptZCcOIcHEXViP4iraI6dybiGDlmeF92WQJdI7l4Esg4W4Wp17
JFWNHbylKoFB0fe2b4q5pzaXMBwNue4BKKvua51NBctRy4LZYwiGvVJplEbjBU7v
wCAS0X4m72y2JvKog9/HfGKo2rZ9se0wFe9mMkjj0wuKkDh91pOzsBZ/0PW0zHci
2q9yJVxF0b41e9+raXa8kvRjxF7EEAuUr9Ov2wIDAQABAoIBAQCPmP4rjyRx8jQr
9AFKY7p00XZBCYpZAdorEiMtMc6PtkJyfA/qpOoEMyBbnqlGUj5Iyp29t1mpR7LJ
kiMECrP/F/jaycxEErlZ1b3HDyYivP4/P9OVPbKS/qZbO4R5yRCtBdTHpVCFzY5f
31E/UUM9uO23q0NMRisrBZvq6GQS5bPIbV/JHJIj1Xd65pZQKQMlRKdXnQGWANV6
4i6Yjcy8v/hqI4wxiwxGlAC26+d1Ow4sdHsMiRmA31vhJNMktdVfT3emyiIlLwoi
Oolbak9CpV2bvtN6iL0Hy4ek0TZp7QPzp7MT4Bhcf8jj9ykxL51SplJoOh2xVwfF
U4aaf1mJAoGBAPKP3an+LFPl8+Re8kVJay7JQrNOIzuoDsDbfhVQMJ9KuodGBz8U
YaUeK8iYZFRuYB/OuIqoDiFnlcdC441+M9VRMhuKwq1rLUOz92esyfiwn8CNzEnT
bJKDPvLocGtpRrN+2iqy+/ySk0IX7NUtsB2/8KXLXImY3ecTafjjqv4dAoGBAMn8
yM03RuBOTXsxWRjPIGBniH0mZG+7KdEbBGmhvhoZ8+uneXJvNL+0xswnf6S4r1tm
mEWM1PldE0tPbRID148Mm2H+tCv7IwtpXSRTKEb175Xkj+pIcFtBC1bkGdNv8DJW
BdkKVnDD2h6rND1IOHatBNjW+CO+2R3aZPUxBGRXAoGAfWu0QzTg+NS7QodxoC/x
UvTQH2S0xSEF1+TmkeCv832xa0bjclN4lec+3m8l2Z5k5619MHzrKYylHq5QeRYb
eR6N2T3rob38XriMobfviz7Qq8DmM/o1dqCUiQd1MaTy4NcjudZog1XK/O7gD+6a
1RctOJ0pkSBRBS29qusVvGUCgYEAtvsDRbUvxf/pfRKlbi4lXHAuW4GuNvHM3hul
kbPurWKZcAAVqy9HD+xKs6OMpMKSSTDV/RupzAUfd3gKjOliG7sGAG5m9fjaNHpM
4J1cvXwKgTW/kjPxZRm1lg+pvbuIU3FOduJAkIM8U9Aw0NteG1R+MZn8zRUVR1AT
aXPwUJ0CgYEA6Fpq8/MFJyzpcvlxkZSfZOVFmkDbE3+UYkB0WAR0X7sTdN74nrTf
RnmMXhcdJ7cCPL6LJpN82h62XrLVwl7zEBXnVfhSsXil1yYHHI5sGXbUFRzaNXNl
KgeanQGV/sG+nd/67uvHhZbifHVDY/ifsNBnYrlpu6q3p+zhQydfkLE=
-----END RSA PRIVATE KEY-----`

const testSignerX509Cert = `-----BEGIN CERTIFICATE-----
MIIDeTCCAmGgAwIBAgIJAMSRCvyhZiyzMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNV
BAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxFDASBgNVBAoMC0V4YW1wbGUu
Y29tMRcwFQYDVQQDDA5FeGFtcGxlIElzc3VlcjAeFw0xNzA0MjYxODAyMzJaFw0y
NzA0MjQxODAyMzJaMFMxCzAJBgNVBAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENp
dHkxFDASBgNVBAoMC0V4YW1wbGUuY29tMRcwFQYDVQQDDA5FeGFtcGxlIElzc3Vl
cjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL9ieOuCqGGzgzCG7ZE1
efIOv9EE3VCGIDsJ8z3WjDVbQjsU4kAyFhG86r9RxD/YX87mkih1B7P/dXuCY9qm
YIUsDxyxu0ys7vvwkSvbGvY76BhFcYOso4mz53Uxri1abWQnDiHBxF1Yj+Iq2iOn
cm4hg5ZnhfdlkCXSO5eBLIOFuFqdeyRVjR28pSqBQdH3tm+Kuac2lzAcDbnuASir
7mudTQXLUcuC2WMIhr1SaZRG4wVO78AgEtF+Ju9stibyqIPfx3xiqNq2fbHtMBXv
ZjJI49MLipA4fdaTs7AWf9D1tMx3ItqvciVcRdG+NXvfq2l2vJL0Y8RexBALlK/T
r9sCAwEAAaNQME4wHQYDVR0OBBYEFP9MhquAFRFLT7fzbru/pHUZd7izMB8GA1Ud
IwQYMBaAFP9MhquAFRFLT7fzbru/pHUZd7izMAwGA1UdEwQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBAAS+HXeUf/WG6g2AbNvd3F+8KkoWmNnRZ8OHuXYQxSQeXHon
Bi0CAc7BZo43n9GSOy4mW0F6Z3JVkK06gH3pFRoKkqqpzk5WaCIYoofRRIOsF/l6
tng3ucauQ3wYGftwid623D6nnbkhPj0jmTyGD6d772dueWEneR2JcN/5G7Xf8HEl
a0fmpm1BG1ZrT2Vp4cb50VeFH+oZn9UW6j+w3Lx4D6pwJvJ11MFjkIfw7Q1hl0j9
Unc9jsYhX7DR3SV8vcFqduUmSH8vdc/zJEk76T2D+qe1aWqtr84QpxXBTrIKvSXD
igkmavdG2gu3SpbFzNxuVCrxQ88Kte0xYJTe7vY=
-----END CERTIFICATE-----`

/*
const testSignerPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/Ynjrgqhhs4Mwhu2RNXnyDr/RBN1QhiA7CfM91ow1W0I7FOJAMhYRvOq/UcQ/2F/O5pIodQez/3V7gmPapmCFLA8csbtMrO778JEr2xr2O+gYRXGDrKOJs+d1Ma4tWm1kJw4hwcRdWI/iKtojp3JuIYOWZ4X3ZZAl0juXgSyDhbhanXskVY0dvKUqgUHR97ZvirmnNpcwHA257gEoq+5rnU0Fy1HLgtljCIa9UmmURuMFTu/AIBLRfibvbLYm8qiD38d8Yqjatn2x7TAV72YySOPTC4qQOH3Wk7OwFn/Q9bTMdyLar3IlXEXRvjV736tpdryS9GPEXsQQC5Sv06/b camilo_viecco1@localhost`

const testUserPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyNPX6TFk3mMO/xDv/hcsEv7IITV3U3k1sV+ytjde6MLECV/L
O+ixlSHVXmK1oOEEpmJaX+hFUgqcf32wms67BuxSVU0YRMcxW0U/WrJr80vr4l0m
0r52r4Ts/6WoocmjLFTylb9uLxejDrPA4H8HoXCgj4yqCD55WF2WmXMtOSjnGZrL
2LtpDTj+rEowxRfq7vk/gy6dw1BsPjD6+OSLke4g54V4ZJaslJ9He6LtKzh18/Rn
RyM6a/gwKEBpkw5KW0BKNOu0Y37uNOoGC/KVRQ9Re2rAo1N/ZZUAnFPxxsj8puX2
tvTbm8NHc2WVxmVFRWpcaNNmDDOz/SOmY3grLwIDAQABAoIBAFX0ZcsHOxb76uU8
yJtGK7UNm3arPaFalaKPRRw8YsDY67Lfb0r681bTHlHBid+Lr8PPAMNf1JuiswzW
LQp1RRNXfn3H+4UkhHl+D/mvuAhwDEvcdstofb/t8soQizaD6PUGfrWdM3mwcjfO
s9TiSc/NNst59ySEKMerdtPCui5mEiLP6P7YWXWlK4DrLbYsrUcichZWaLybTH7S
tOs6nhQlI4yDviAqwIcBa/d/a0BRY8Fngf4oLYetTI1y1GPQ+Hwzev4jJL52yWxH
YZgEeS4IB1y9D6FmuP/a9wIx1FJhMqGKxOYG4gI+lSIfhBJqll2jKQaTN1/YVDBU
bowg8LECgYEA/CXBEreAT3VP4XzFGFt2dMOL84zCSdFqrIElLSNBWW2t8JoSPB/W
J57CQaclV+ItQzBV/IL9G5TyHG7mTnRCmh/aPaxnVaiB4ONyzuADC87M7O5bGR3b
7M7o8nkoXBdbTPabgohuw2NNcKEPsgJfKVwW75GYpjMD1a8sKu6qx/0CgYEAy+Vb
adAoDycVE0X7t3U8dC6IUYXMAD6+Jd0RwcURYMV4LH2lFC9/VMY9z2i60MZPHhN7
odIXvWf21WarxZk5pHdg8giBtx2Ymyv3aIiWgW0MeoVRZhRnbuYAHwd4/dFBgSeZ
REvpz6LHgmBSErHyf3+XAqott5aaMUb4WbN8+ZsCgYEAmv0p/LNG75CQlW34SMyP
t54rfH1dP7q182s+yswM80dzz50k8EgxfxEbHvf7AFZKtC4V7K0nn7iiSc/xSPA1
sD88CwTaT9DQZMfqXjdcJ/nqBQlOfdXYxWs5zTGkGVdSC7DaThZG31s+0qht2WGT
1PyCLKg2SJK7HLIcWBd0apECgYEAnHz0svqCtFZ/k2JD9iLxeg34q/DviESfdbn9
FeXlF4uXVzY7i4mExZC9AcHUl8WMFX5IhgMUG1d+l3yMW0Tle7fv3PLwc5Uwee+9
nCowsTb7u9E0jw8b735xG1+F2fBPwQueU0+cLLM3QnYgp56Rio9nXDE2k0/wGd/p
Xhcm1P8CgYEAxIXFqJ1rWQh4MV9abLDFQ+cdLxn6tvmskxCA9LGcyaA+fFbcRx25
mYIAaRZI5SHjgMjeicDgPmY+xuNMSKcgd2C4uYJiW5xo7r+7SwcIyo6J8nZeZAVK
bxrMjPsOnAt3Tq7G0tlACxBOBhf+dcDW7D8/8EE6klKr2OrrT2Yag6k=
-----END RSA PRIVATE KEY-----`
*/
const testUserPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI09fpMWTeYw7/EO/+FywS/sghNXdTeTWxX7K2N17owsQJX8s76LGVIdVeYrWg4QSmYlpf6EVSCpx/fbCazrsG7FJVTRhExzFbRT9asmvzS+viXSbSvnavhOz/paihyaMsVPKVv24vF6MOs8DgfwehcKCPjKoIPnlYXZaZcy05KOcZmsvYu2kNOP6sSjDFF+ru+T+DLp3DUGw+MPr45IuR7iDnhXhklqyUn0d7ou0rOHXz9GdHIzpr+DAoQGmTDkpbQEo067Rjfu406gYL8pVFD1F7asCjU39llQCcU/HGyPym5fa29Nubw0dzZZXGZUVFalxo02YMM7P9I6ZjeCsv camilo_viecco1@mon-sre-dev.ash2.symcpe.net`

// The next was extracted from the testUserPrivateKey above : openssl rsa -in userkey.pem -pubout
const testUserPEMPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyNPX6TFk3mMO/xDv/hcs
Ev7IITV3U3k1sV+ytjde6MLECV/LO+ixlSHVXmK1oOEEpmJaX+hFUgqcf32wms67
BuxSVU0YRMcxW0U/WrJr80vr4l0m0r52r4Ts/6WoocmjLFTylb9uLxejDrPA4H8H
oXCgj4yqCD55WF2WmXMtOSjnGZrL2LtpDTj+rEowxRfq7vk/gy6dw1BsPjD6+OSL
ke4g54V4ZJaslJ9He6LtKzh18/RnRyM6a/gwKEBpkw5KW0BKNOu0Y37uNOoGC/KV
RQ9Re2rAo1N/ZZUAnFPxxsj8puX2tvTbm8NHc2WVxmVFRWpcaNNmDDOz/SOmY3gr
LwIDAQAB
-----END PUBLIC KEY-----`

// The next was generated by: openssl genpkey -algorithm RSA -out /tmp/weak.pem -pkeyopt rsa_keygen_bits:1024 && openssl rsa -in /tmp/weak.pem -pubout
const weakPEMPublicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyB3ZqDjhdfZdFF7Nz7PR1JuYP
AJDDHXRFEMiChDZku9Aq0sPuNeCx4WmodlrS9hCI0YsnGs2fWaob2MSSue72Ju8S
DpW3/LJjOLPu7/T5g3Mm2XTmlCRSvcWvT7du88xRrl3xZv7Txg1iOTOY/CRM9ABQ
i3eakMjGBzvVqsglowIDAQAB
-----END PUBLIC KEY-----`

// openssl genpkey -algorithm RSA -out /tmp/weak2.pem -pkeyopt rsa_keygen_pubexp:3 &&
const weakPEMPublicKeyExponent = `-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA4iq+jaUcmhJIzXYNYUjB
yUChddBywXqmaAwo8VR5hGpZJ8yXFaFb4FswalvK54DAr6JVHKmzKh0+ua29WJX3
EGr7VTx4ceaMZJ436B3JFgtGhvH9FpiSRwy4UhuK8zae1tvRtojXZPys2Ej3fTxv
rrOkpKOyOR4PRe/VmCZV/gthE5MRxpB5sywWJJ/MQKdKCH252bGq8gpYtd6gAXOg
DhV+rrj+h1k9EaIv+VSQ98XGm97NK3PEkolWk5UngF3Qwt5qPDeGjpf4zyhej0lF
1qsg34sKSoKm682HPH2dFe5MmRMIneb3RL5T8nDr3ia9/utpVThM4NemN/4l6350
KwIBAw==
-----END PUBLIC KEY-----`

// now other valid sshKeys : ssh-keygen -t ecdsa
const ecdsaPublicSSH = `ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD+IdwZ/LsQhxE3soSMoCNOtqftjUgMoy7nqAukSL9MuULIbspoWRvF/bxDaaJf9dcz+mK/ILC5NXxNs36oYNOs= cviecco@cviecco--MacBookPro15`

const ed25519PublicSSH = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDdNbfR67CJ0/iB5a5lQfZowi3VTrkDu7/rpMNKfHFPs cviecco@cviecco--MacBookPro15`

// we do not support dsa
const dsaPublicSSH = `ssh-dss AAAAB3NzaC1kc3MAAACBALd5BLQoXxeJHHMQpJzk283nbne65LQiFNPeH6VuNiNEGZI6N3KlQsijYK1oJX2R3oTDEhqEjQsdNa6s++eGbh2z6U3Xwu34odNCFJekKB3qZN7/gqWXzBcgFvir//edTCrN0evzbTedtjz3pB5KlB6OSsnntm/y6E/j45Q3ijGTAAAAFQCjyfpjPi4gmdskz5/cQZbGirVzmwAAAIEAr/LZ7rvsgdnQ1/x5NpJAGEy7QlxfjGfIUo2a57WpDvcjiQmpa9VRCF0ziF3XSv2iDfWZ19qPrbxAp4FIe+xXF3kR0XMmDQzeEZsBzl8pNe7ZxLBHKFX8ZL66VBngYJL2a4v84QoPCpXDJ1hWd7t+okqkFj/a+99cuWj65jk2zLkAAACAPbtpnU39ZioS+9HolaGqudhTfToNAVsVPwj7uiuqiR2OTywbR0WpDPs7zrYsJTzIviuuEXzTVLFWBDR6EwXQdg9Acz+uRRiiZ58e7kN7qv+hQ3FBT3W214A0EVkRJMozowYhzS4HM0x/LrxlNHHFpzMu/njkNfNYDJTK4I47BO0= cviecco@cviecco--MacBookPro15`

// next rsa key generated by openssl : openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048
const pkcs8rsaPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDPcau+5MKq9/mF
cWXw7R6UjP2tUwFrXv/JZaQpix5MHTztl3B+MpWwphfNTiTIDo3lzD3l7TklI5rp
KRQ6Lddsrp2cWtOi+YHOfy1R6CavMjFhxcjNiD0iXz/Dy34Na5MWyDPLGP8RQRuK
malZIvkDvNAqQ95PkOzj1HP0ZL/sg4JJaBRkZW7CQCslZj5lRNDj1Gmg7yvSoDlS
My4DPfl13e0DHShHEwLumikxqAE5gN/ijCbRBjouWLTKxffTawJPkYFb2g0PRXsv
rJYz+FXnpfMny63mkBbjiLiPgeYiy0t2fO/sVlXsnPZ5owIImGj3nXb5+rJ3pxVg
moCuDpnRAgMBAAECggEAXL8Qr29tzazCxbO2hSou0vHadUS4TL4TlIK6C8zkRdmI
pR1hMTsCjBEmcScv8LX5ITXYstUGCKHLn9U68uwN9cx4MTC2kJYHQEDCDW3C5e+F
/pXEOohf9N8rDioL+IoRIE1wQqyxVZCLdMNQ4MZvGQmw9ESVv3MnRpF1Kl5lJKO1
BEvH38DcWapL4QeQUAnT9rKppgctwG0xkE9REMkeTks46EFa8k+IL6Fw5Vyn4xUX
zcIBQfPi5uPpGD1mlBv80iQlXjWb7o3J8OKXfd8lTKWYV2JPruteueEUsyHQ5V24
8XPc0PHeey6pVvj/5tQD6kcsXSwP7Bhx+NRRKonqRQKBgQD1SRCQmGtdzCHt1UQS
ok47ApmrFH0vT07LAPpW5VBXP4lpwCePKO5jHXRGZWijWp4QT6+ktqx74rifrj4w
9vi5j9AhVYIIJVMB02ZVeg8jv6DyvsgnOucdB6m6YjbJkOc3BDnHBoFLOM8DakmA
rSNzN/+1ig2pqw7BR9s3+Sv8UwKBgQDYgXCquUg8AyOiV/4pxeXIzXhIt3ncOY2K
eM9bPEdVqiRTs9IFCfTmI47Gznh6Rs/GLJAIsf7oMxXCi+C8zylQbXrxRc8TY7UD
rV2e6isCb+qbhn7AMTq4KfaT1FjjsyWc2Gg8oJzKNv8f+sVxLZJGRiM3BjAtONMX
oojM/AvsywKBgQCHy+Ky2t+eN1SVcpvUYS1EeEURNS+1UIgD1c/C6gPXueJevLZq
CLQqBXWJP711qsaVqzhHzaaik7u5E+N0glbjjN4ihk+OKPPSr/IY4pGdLgtyOPNg
3Lh1Fvf9q0A/ycxoZhuCt3Q/a/0YG/EDn1dgA6G7JOo5g+2QTjLswzN55wKBgBWA
vZznLApx0V81WBP0CL9p0NGAD4VU3f7rwsRv9zHF5Te++1Puyjj1PR/3r7WNROOM
131VmFidgkLBO7/k31iSlwxRf6CQXZEQ7eRzo3Ppg6aQtBQIj6ls2YWTKITs7QZn
4+pplUjsL2iQsn1sJkP+gU7cuXo0U5rcVLPvMIwDAoGAfY4hWZUPYKX1XWBt3Qfw
oWn0d8JAYib6d4SwL/H+LeQ7Qp9+/MArZ5xWVRLHvL8E9LNbUN6S11qKKvCnTqU+
Qba/iC2s8vfVG9TGl39tp/jFWl+33LOtE3tdCE5iBoxI8qv1bm6SIXefxJcEX87L
DuL8avr+q9CJgcMKoNEyiG0=
-----END PRIVATE KEY-----`

// openssl genpkey -algorithm EC -out eckey.pem -pkeyopt ec_paramgen_curve:secp384r1 -pkeyopt ec_param_enc:named_curve
const pkcs8ecPrivateKey = `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDA0fA/C+NNTaTx9/q2N
FerrGHqvHsEiecRKJbs3idQVmy1CNwTuvpkWRvIj2BtamuKhZANiAATHX6b2L3WD
/trT/Emgw/11Ihy7cR2ya9mkX1GgogceX6UACg8OSX96ZD93vZ3Do/NrGq3LvAet
IGODZM6zCMhJ4bfLYDt66LtwEiHpQEiftLqU2tZDYBrGLEcBCKKIsTw=
-----END PRIVATE KEY-----`

// openssl ecparam -name secp384r1 -genkey
const rawECPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBFuaVA8eON9OoBdzxMJ28usx5QzJwn7SDL+UWQc/FAbsNeNqDRRugi
bV6VGEJUy+KgBwYFK4EEACKhZANiAAT/x3jLa1y5v8XtRTnnY9/bC3nOP65kboQe
RBm1g0vfLOjV1tPs5/0QMy7ANExMLGtzIJidWWWzIzw2rx4WC7xcIkJ+iWFIIFNy
S9RSPfwJS7+Zr8LP4H6APpstQWZEXOo=
-----END EC PRIVATE KEY-----`

// openssl genpkey  -algorithm ED25519 -out key.pem
const pkcs8Ed25519PrivateKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHoHbl2RwHwmyWtXVLroUZEI+d/SqL3RKmECM5P7o7D5
-----END PRIVATE KEY-----`

// ssh-keygen -t ed25519
const keygenEd25519PrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDICn5DsRIjR4GyKVUPucWJ7A3+7TKoNfK/ImglUc6shQAAAKDzYr6j82K+
owAAAAtzc2gtZWQyNTUxOQAAACDICn5DsRIjR4GyKVUPucWJ7A3+7TKoNfK/ImglUc6shQ
AAAECdSciYZnODYp2QC0s838bYh8d2XEOuvBOqcOEA6MUjL8gKfkOxEiNHgbIpVQ+5xYns
Df7tMqg18r8iaCVRzqyFAAAAHWN2aWVjY29AY3ZpZWNjby0tTWFjQm9va1BybzE1
-----END OPENSSH PRIVATE KEY-----`

// We should not be using p224 keys except for testing
// openssl ecparam -name secp224r1 -genkey
const testP224Privatekey = `-----BEGIN EC PRIVATE KEY-----
MGgCAQEEHNBN+rQ+YDZ27lRc6tHu5myU+kq8Tetzodw4bfOgBwYFK4EEACGhPAM6
AARWr9bjMJaYzHyQjD2za224ohGmBg6/6H5pomxWY8fkAfZy/DmjRRCD72pX86xp
PSDtPZDi9/ao4g==
-----END EC PRIVATE KEY-----`

// The tranformation requires the full information of the private key
//
//	openssl ec -in private.ec.key -pubout
const testP224PublicKey = `-----BEGIN PUBLIC KEY-----
ME4wEAYHKoZIzj0CAQYFK4EEACEDOgAEVq/W4zCWmMx8kIw9s2ttuKIRpgYOv+h+
aaJsVmPH5AH2cvw5o0UQg+9qV/OsaT0g7T2Q4vf2qOI=
-----END PUBLIC KEY-----`

const testDuration = time.Duration(120 * time.Second)

// SSSD tests do require some setup... in this case we do some checks to ensure
// that actually trying to even do this makes sense
func canDoSSSDTests() (string, error) {

	//check for sssd binary
	if _, err := os.Stat("/usr/bin/sss_ssh_authorizedkeys"); os.IsNotExist(err) {
		return "", nil
	}

	// check for a username in our internal test box
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	username := usr.Username
	target := "9Z5PHgLIlUMUnu0MUv2p+RuJCwNXG9Lg/3tXpOau7UM="
	h := sha256.New()
	h.Write([]byte(username))
	b := h.Sum(nil)
	targetUser := base64.StdEncoding.EncodeToString(b)
	//t.Logf("targetUser ='%s'", targetUser)
	if targetUser != target || usr.Username != usr.Name {
		return "", nil
	}
	return username, nil
}

// func GenSSHCertFileString(username string, userPubKey string, signer ssh.Signer, host_identity string) (string, error) {
func TestGenSSHCertFileStringGenerateSuccess(t *testing.T) {
	username := "foo"
	hostIdentity := "bar"
	goodSigner, err := ssh.ParsePrivateKey([]byte(testSignerPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	certString, cert, err := GenSSHCertFileString(username, testUserPublicKey, goodSigner, hostIdentity, testDuration, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("got '%s'", certString)
	if !strings.HasPrefix(certString, "ssh-rsa-cert-v01@openssh.com ") {
		t.Logf("wrong prefix on stringification rsa-cert")
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != username {
		t.Fatal("invalid cert content, bad username")
	}
	// now test with an Ed25519
	goodEd25519Signer, err := ssh.ParsePrivateKey([]byte(pkcs8Ed25519PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	certString, cert, err = GenSSHCertFileString(username, ed25519PublicSSH, goodEd25519Signer, hostIdentity, testDuration, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("got '%s'", certString)
	if !strings.HasPrefix(certString, "ssh-ed25519-cert-v01@openssh.com ") {
		t.Logf("wrong prefix on stringification for ed25519")
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != username {
		t.Fatal("invalid cert content, bad username")
	}
	// test with non nil custom extensions:
	extensionTest1 := map[string]string{"hello": "world"}
	_, cert, err = GenSSHCertFileString(username, ed25519PublicSSH, goodEd25519Signer, hostIdentity, testDuration, extensionTest1)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for key, value := range cert.Permissions.Extensions {
		if key == "hello" {
			found = true
			if value != "world" {
				t.Fatal("extension value is invalid")
			}
			break
		}
	}
	if !found {
		t.Fatal("custom extension not found")
	}
	// invalid extension blank name.. should NOT fail
	invalidExtensionTest := map[string]string{"": "world"}
	_, _, err = GenSSHCertFileString(username, ed25519PublicSSH, goodEd25519Signer, hostIdentity, testDuration, invalidExtensionTest)
	if err != nil {
		t.Fatal(err)
	}

}

func TestGenSSHCertFileStringGenerateFailBadPublicKey(t *testing.T) {
	username := "foo"
	hostIdentity := "bar"
	goodSigner, err := ssh.ParsePrivateKey([]byte(testSignerPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = GenSSHCertFileString(username, "ThisIsNOTAPublicKey", goodSigner, hostIdentity, testDuration, nil)
	if err == nil {
		t.Fatal(err)
	}
}

func TestGetUserPubKeyFromSSSD(t *testing.T) {
	username, err := canDoSSSDTests()
	if err != nil {
		t.Fatal(err)
	}
	if len(username) < 1 {
		t.SkipNow()
	}
	pk, err := GetUserPubKeyFromSSSD(username)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("got ''%s", pk)
}

func TestGetUserPubKeyFromSSSDFailUserWithNoSSSDPublicKey(t *testing.T) {
	username, err := canDoSSSDTests()
	if err != nil {
		t.Fatal(err)
	}
	if len(username) < 1 {
		t.SkipNow()
	}
	_, err = GetUserPubKeyFromSSSD("THISISANINVALIDUSER-FOOBARBAZ")
	if err == nil {
		t.Fatal(err)
	}
}

func TestGenSSHCertFileStringFromSSSDPublicKeySuccess(t *testing.T) {
	username, err := canDoSSSDTests()
	if err != nil {
		t.Fatal(err)
	}
	if len(username) < 1 {
		t.SkipNow()
	}
	hostIdentity := "bar"
	goodSigner, err := ssh.ParsePrivateKey([]byte(testSignerPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = GenSSHCertFileStringFromSSSDPublicKey(username, goodSigner, hostIdentity, testDuration)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenSSHCertFileStringFromSSSDPublicKeyFailUserWithNoSSSDPublicKey(t *testing.T) {
	username, err := canDoSSSDTests()
	if err != nil {
		t.Fatal(err)
	}
	if len(username) < 1 {
		t.SkipNow()
	}
	hostIdentity := "bar"
	goodSigner, err := ssh.ParsePrivateKey([]byte(testSignerPrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = GenSSHCertFileStringFromSSSDPublicKey("THISISANINVALIDUSER-FOOBARBAZ", goodSigner, hostIdentity, testDuration)
	if err == nil {
		t.Fatal(err)
	}
}

func TestValidatePublicStrengthKey(t *testing.T) {
	//good rsa
	userPub, err := getPubKeyFromPem(testUserPEMPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := ValidatePublicKeyStrength(userPub)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("should have been valid")
	}
	weakPublic := []string{weakPEMPublicKeyExponent, weakPEMPublicKey}
	for _, weak := range weakPublic {
		weakPub, err := getPubKeyFromPem(weak)
		if err != nil {
			t.Fatal(err)
		}
		valid, err = ValidatePublicKeyStrength(weakPub)
		if err != nil {
			t.Fatal(err)
		}
		if valid {
			t.Fatal("should NOT have been valid")
		}
	}
	//Now ssh
	validSSHPublic := []string{testUserPublicKey, ecdsaPublicSSH, ed25519PublicSSH}
	for _, validSSHKey := range validSSHPublic {
		userSSH, _, _, _, err := ssh.ParseAuthorizedKey([]byte(validSSHKey))
		if err != nil {
			t.Fatal(err)
		}
		cryptoPubKey := userSSH.(ssh.CryptoPublicKey).CryptoPublicKey()
		valid, err = ValidatePublicKeyStrength(cryptoPubKey)
		if err != nil {
			t.Fatal(err)
		}
		if !valid {
			t.Fatal("should have been valid")
		}
	}
	//now invalid key type:
	//dsaPublicSSH
	userSSH, _, _, _, err := ssh.ParseAuthorizedKey([]byte(dsaPublicSSH))
	if err != nil {
		t.Fatal(err)
	}
	cryptoPubKey := userSSH.(ssh.CryptoPublicKey).CryptoPublicKey()
	valid, err = ValidatePublicKeyStrength(cryptoPubKey)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("should NOT have been valid")
	}
}

func setupX509Generator(t *testing.T) (interface{}, *x509.Certificate, crypto.Signer) {
	userPub, err := getPubKeyFromPem(testUserPEMPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	//caPriv, err := getPrivateKeyFromPem(testSignerPrivateKey)
	caPriv, err := GetSignerFromPEMBytes([]byte(testSignerPrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	caCertBlock, _ := pem.Decode([]byte(testSignerX509Cert))
	if caCertBlock == nil || caCertBlock.Type != "CERTIFICATE" {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return userPub, caCert, caPriv
}

func derBytesCertToCertAndPem(derBytes []byte) (*x509.Certificate, string, error) {
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, "", err
	}
	pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
	return cert, pemCert, nil
}

// GenUserX509Cert(userName string, userPubkey string, caCertString string, caPrivateKeyString string)
func TestGenUserX509CertGoodNoRealm(t *testing.T) {
	userPub, caCert, caPriv := setupX509Generator(t)

	groups := []string{"group0", "group1"}
	derCert, err := GenUserX509Cert("username", userPub, caCert, caPriv, nil,
		testDuration, groups, nil, nil, testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
	cert, pemCert, err := derBytesCertToCertAndPem(derCert)
	t.Logf("got '%s'", pemCert)
	if cert.Subject.CommonName != "username" {
		t.Fatalf("Subject.CommonName: %s != username\n",
			cert.Subject.CommonName)
	}
	groupsMap, err := x509util.GetGroupList(cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(groupsMap) != len(groups) {
		t.Fatalf("number of groups: %d != %d\n", len(groupsMap), len(groups))
	}
	for _, group := range groups {
		if _, ok := groupsMap[group]; !ok {
			t.Fatalf("group: \"%s\" not present in certificate\n", group)
		}
	}

	// TODO: check values
	// 2.  basic constraints true
	// 3. is ca false
	// 4. valid key usages
	// 5. valid eku
	// 6. kerberos realm info!
}

func TestGenx509CertGoodWithRealm(t *testing.T) {
	userPub, caCert, caPriv := setupX509Generator(t)
	/*
	 */
	realm := "EXAMPLE.COM"
	derCert, err := GenUserX509Cert("username", userPub, caCert, caPriv, &realm,
		testDuration, nil, nil, nil, testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
	certString := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert}))
	t.Logf("got '%s'", certString)
	//t.Logf("got %+v", userCert)

	// TODO: check values
	// 1.  commonName must match "userame"
	// 2.  basic constraints true
	// 3. is ca false
	// 4. valid key usages
	// 5. valid eku
	// 6. kerberos realm info!
}

// GenSelfSignedCACert
func TestGenSelfSignedCACertGood(t *testing.T) {
	validPemKeys := []string{testSignerPrivateKey, pkcs8ecPrivateKey, pkcs8Ed25519PrivateKey}
	publcKeyPems := []string{testUserPEMPublicKey, testP224PublicKey}

	for _, signerPem := range validPemKeys {
		caPriv, err := GetSignerFromPEMBytes([]byte(signerPem))
		if err != nil {
			t.Fatal(err)
		}
		derCACert, err := GenSelfSignedCACert("some hostname", "some organization", caPriv)
		if err != nil {
			t.Fatal(err)
		}

		cert, pemCert, err := derBytesCertToCertAndPem(derCACert)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("got '%s'", pemCert)

		derCaCert2, err := GenSelfSignedCACert("some hostname", "some organization", caPriv)
		if err != nil {
			t.Fatal(err)
		}
		cacert2, _, err := derBytesCertToCertAndPem(derCaCert2)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(cert.RawSubject, cacert2.RawSubject) {
			t.Fatalf("subjects across generations should match")
		}

		// Now we use it to generate a user Cert
		for _, publicPem := range publcKeyPems {
			userPub, err := getPubKeyFromPem(publicPem)
			if err != nil {
				t.Fatal(err)
			}
			_, err = GenUserX509Cert("username", userPub, cert, caPriv, nil,
				testDuration, nil, nil, nil, testlogger.New(t))
			if err != nil {
				t.Fatal(err)
			}
		}
		//t.Logf("got '%s'", certString)
	}

}

func TestGetSignerFromPEMBytesFail(t *testing.T) {
	_, err := GetSignerFromPEMBytes([]byte("not pem data"))
	if err == nil {
		t.Fatal(err)
	}
	_, err = GetSignerFromPEMBytes([]byte(testUserPEMPublicKey))
	if err == nil {
		t.Fatal(err)
	}
}

func TestGetSignerFromPEMBytesSuccess(t *testing.T) {
	_, err := GetSignerFromPEMBytes([]byte(pkcs8rsaPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	_, err = GetSignerFromPEMBytes([]byte(pkcs8ecPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	//rawECPrivateKey
	_, err = GetSignerFromPEMBytes([]byte(rawECPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	// Ed25519 from openssl
	_, err = GetSignerFromPEMBytes([]byte(pkcs8Ed25519PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	// keygenEd25519PrivateKey
	_, err = GetSignerFromPEMBytes([]byte(keygenEd25519PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetPubKeyFromPem(t *testing.T) {
	_, err := getPubKeyFromPem("not pem data")
	if err == nil {
		t.Fatal(err)
	}
	_, err = getPubKeyFromPem(testSignerPrivateKey)
	if err == nil {
		t.Fatal(err)
	}
}
