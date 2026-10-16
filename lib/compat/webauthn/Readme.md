This path contains a subset of go-webauthm at version 0.16. We have added this as until now the webauth internal structured have not changed and as 0.18 they have. 

Since we use gob to store this data struct we need to keep the old version so that we dont break current users (backwards compatibility).
As of Oct 2026 it seems like we can transform the old values into new structs an vice-versa thus we will keep using the old serialization until something breaks.
