package sshagent

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/Cloud-Foundations/Dominator/lib/log/testlogger"
	"github.com/Cloud-Foundations/npipe"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const demoCert = `ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgAAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAADAQABAAABAQDJQcViFiExQ0zSL53MSnTSIF+hkcjBSI1zQBZNIDLECvCfWkUq7RAnlLU06ZFLc/SMu8gL5jyb6ZVNh/I2ziiWkqrKiB1QM+zG4QZAKawakxtEECWzMEMMsRGHBVBr98pCYTRcUS8WFU3vhnGCFl+JwyZ1tJWbvlZJzxK49Pxib0gPtATYbDfH9Zgvg7yU5+DORg0v8oZXVquuaLo0e24hXyf17Zr9nGd8pZL/mCAOPTrhPmtC2hcZs4xoQ5o1EoeX3wAW2dmZTpF8XF0NHSI3yzF5iKU4QKI0rRRuZ1GgbxG/LFxloiWeAU9TL9Hh+KhXog6ub79+4uTXgm0N4qOzXf1jWNRTQXMAAAABAAAAM2tleW1hc3Rlci5kZXYtY2xvdWQtc3VwcG9ydC5wdXJlc3RvcmFnZS5jb21fY3ZpZWNjbwAAAAsAAAAHY3ZpZWNjbwAAAABd/WNYAAAAAF39Y3YAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAABlwAAAAdzc2gtcnNhAAAAAwEAAQAAAYEA+vsfsD47iljOwPGgmYBnYhV0WXaS0WZPiqbzQXvZ17vRh851mKzyF1lQi5fsqer99JXc0VIgsx57JFdEeFs48YtiwipVSMKcdme4FZPF52X/zAB3b5JXxwdrK6VrBlEDSYcQlXjhcHicYS0iC5IesvldMmfGct7dgCwqxwMjhGIc/0YB4JljGL8c6Eo+cJ0terWNwHbd7DrtwzEauOXSLCozdG40j48nC+k0BlrxPQSvB7IqMhFQjSLVm4ePuJH6+C99lOksPbMryuD9vZLx5z20qC7LAirlr7Smi4yPaihY/rC94ZbGQlOZLxxD1Vg7nRMVtsAPIZuktsKSDqiP1Gv9uA4ZuzCopnql4jqDtMMz3oeyGikH3M8uvB5pNkvKLm4/MCMI8WSAm4S/3MZe2Q9RFmPy2R/oOW3/fIL5dJgt4BVhFcgOGWcDZMyJVdTWV4m15HbKriYNuP/mTDLTGrf5KnfHYvZc7qFUQDlfavNL+0BYtuYx4yoF0yewL+5nAAABjwAAAAdzc2gtcnNhAAABgNm+194XVwc2Krw01+xiPJJz6XKSxYzz0eY9MfLD93lQuizf8V57996FhZ3CSzdiHA9xSnSueDyKjkq5hTJp6cB49pQ5oYjmJv8TTki0TTxqDxiGvlOebFsESV+tZDChpv1T3KuWhJpxAmh4HZYZNekKL/K943v61wcvNmvrKGB/bXqrknw5L6Gdhia7l5vxL466i2XEnLQHDAzb3jgFLNcv5Lc88J2tkyUsNjOR3aF9wD6+MoumfAmiRH7KqiiAyBiq6WO/+txC4v0EiG5i45AXB+zu9jWRWZIpPupeBv+R1RdHVR3+49DyCtXxl9jxrKKsITPhuCwxw1/djpQzCS/SN5v+W81w1NMcsYmnfT5nOuqq5HCynj9sAOfttuBZL3V8PNgIB9uCya2HZpfhFlWyFFMI55iz9MFpglSJkdDYpr4fSqPDp/I/PPq9Ol+bcnKs53YyH7NR9Jog5V6/l1j8N/ddyDf7NNfpH6giXYSNPVFKbIYOfwVkO+M/9HKstQ== /tmp/cviecco-cert.pub`

const demoKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyUHFYhYhMUNM0i+dzEp00iBfoZHIwUiNc0AWTSAyxArwn1pF
Ku0QJ5S1NOmRS3P0jLvIC+Y8m+mVTYfyNs4olpKqyogdUDPsxuEGQCmsGpMbRBAl
szBDDLERhwVQa/fKQmE0XFEvFhVN74ZxghZficMmdbSVm75WSc8SuPT8Ym9ID7QE
2Gw3x/WYL4O8lOfgzkYNL/KGV1arrmi6NHtuIV8n9e2a/ZxnfKWS/5ggDj064T5r
QtoXGbOMaEOaNRKHl98AFtnZmU6RfFxdDR0iN8sxeYilOECiNK0UbmdRoG8Rvyxc
ZaIlngFPUy/R4fioV6IOrm+/fuLk14JtDeKjswIDAQABAoIBAHRGs6t/7Z1wrKmj
KSAmxGfCnH3UpJBHQrIbjMbym2H4kB0BIoUygercV/VCHNfjHp9QvrthQhMyWTh6
Gs7fPUQBaPuquITl+x7MU7guW2jfJRml2qI0eAiVJPNFdrlqaEkBsCbGINY5aNXC
b0IhewE05ruKogVhaqkqIj8KC+cyLZ9b7IaBgZMOpQ4KXCsxx8ir8v88GdtHOSbv
GrhvadfXBdXylE+TVGYB575wuA1u+Zj+GdZ1bHTi9hNG21GS97bm7VsM+aRhvGuw
FNqa0e8KWLzmK7kQGKDpy0Zd/8dUvmTJoXh6Jt+3KEBBf5IuZchCklO/nDw51TD3
aaujCMECgYEA3BPVoCYSDj6CY++4llaDinDahLinjpoK1hOKlHEyptmxSQnJHfL6
h7R7M4RhsA5k0ng7ZCbbjbHVbHFAKuTzf1juDzMneYYqxJ0o8IomaUFow/z+48FY
rGb/sw1yNDsCCvRbjuxsms3l411IzohXVJZ3cTtMCwK4Yrzt1vB4KKcCgYEA6ht/
+6QIN8kOb9KltJENgWcTnWBradDecBf46Ph+JfCJfC16eT2j2TppWNN7TVdd54SZ
Ue/PIrsBXtPSmkGVQrPjqRnSy+rt7EKxZFN59tOvV7+Bvxb7T/Y6JNpSsz0nUnOS
Lh1zbHTtcmaqKjb5KrXp6G1ydSz+aqonXT9aAhUCgYEAs7oa/tO4cRuJfrXZ6CS0
/g1V14e5htK0QMnqpXmgZPRpPP2Z2jSBduvkpVjaMl4+5kc8MXkuWhQ9+HawcZdS
Z9CncZBUD4GLUdALDA22esTpGw1012kh0oG3FnHHr3H1JB8U2q6nrvCxajHXcJuV
vkW3O6iyXFeXX0NtdNgjOQcCgYEAofQoU9Okg8Mpo55cWFBIwY6neSYs6OVAHNfY
sILH8kM3OZrUsW89HJhWLMcQ8+5O3k1TK+X0rBgm2I09ks1wDtcX1fIxbDS4J8vz
oG5HX8QN92xau/GQJj829iu7LphNzbJ6HEDvisZRReVULyQct7lleg/NMNbRosTX
uqCLCgkCgYBMnr50bdqtx2wVDwZD3im+bg6lUAimIdID1UC8lglbK7bUVMGirxka
yN1BQ4nUa6ey0tP0p50BnLr/xQx4VAFk96L2HHgg2VmsvqlTK9LLjhaM83XQ/PLI
DCivzG6GfJ6nBGB+vrbKxkvSbKQqdGvqxunYzABSXEyhwBl25VAiXQ==
-----END RSA PRIVATE KEY-----`

func TestConnectToDefaultSSHAgentLocation(t *testing.T) {
	switch runtime.GOOS {
	case "windows":
		conn, err := npipe.Dial(`\\.\pipe\openssh-ssh-agent`)
		if err != nil {
			t.Skip("Assuming that windows agent is not enabled/wori")
		}
		conn.Close()
	default:
		if _, ok := os.LookupEnv("SSH_AUTH_SOCK"); !ok {
			t.Skip("No Auth Socket present, skipping testing")
		}
	}
	_, err := connectToDefaultSSHAgentLocation()
	if err != nil {
		t.Fatal(err)
	}
}
func TestInsertCertIntoAgent(t *testing.T) {
	conn, err := connectToDefaultSSHAgentLocation()
	if err != nil {
		t.Skip("No Agent Socket/Pipe, skipping test")
	}
	conn.Close()

	comment := "foo"
	key, err := ssh.ParseRawPrivateKey([]byte(demoKey))
	if err != nil {
		t.Fatal(err)
	}
	/*
			insertCertIntoAgent(
		        certText []byte,
		        privateKey interface{},
		        comment string,
		        lifeTimeSecs uint32,
		        logger log.Logger)
	*/
	err = upsertCertIntoAgent(
		[]byte(demoCert),
		key,
		comment,
		30,
		testlogger.New(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	// Call it twice to check for deletion
	err = upsertCertIntoAgent(
		[]byte(demoCert),
		key,
		comment,
		30,
		testlogger.New(t),
	)
	if err != nil {
		t.Fatal(err)
	}

}

// This mocks and agent.ExtendedAgent
type MockExtendedAgent struct {
	keys []*agent.Key
}

func (m *MockExtendedAgent) List() ([]*agent.Key, error) {
	return m.keys, nil
}
func (m *MockExtendedAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return nil, fmt.Errorf("not implemented")
}

// TODO actually implement
func (m *MockExtendedAgent) Add(key agent.AddedKey) error {
	return nil
}

func (m *MockExtendedAgent) Remove(key ssh.PublicKey) error {
	return nil
}
func (m *MockExtendedAgent) RemoveAll() error {
	return fmt.Errorf("not implemented")
}

func (m *MockExtendedAgent) Lock(passphrase []byte) error {
	return fmt.Errorf("not implemented")
}

func (m *MockExtendedAgent) Unlock(passphrase []byte) error {
	return fmt.Errorf("not implemented")
}
func (m *MockExtendedAgent) Signers() ([]ssh.Signer, error) {
	return nil, fmt.Errorf("not implemented")
}

//next are extended
func (m *MockExtendedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *MockExtendedAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func TestDeleteDuplicateEntries(t *testing.T) {
	agentClient := &MockExtendedAgent{}
	_, err := deleteDuplicateEntries("bar", agentClient, testlogger.New(t))
	if err != nil {
		t.Fatal(err)
	}
}
