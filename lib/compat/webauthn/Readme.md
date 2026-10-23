This path contains a subset of go-webauthm at version 0.16. Go webauth made a breaking change in 0.17.0 for dependencias that manually serialize the internals such as keymasterd. 


Since we use gob to store this data struct we need to keep the old version so that we dont break current users (backwards compatibility).
As of Oct 2026 it seems like we can transform the old values into new structs an vice-versa thus we will keep using the old serialization until something breaks.

In addition https://github.com/go-webauthn/ uses the "BSD 3-Clause Revised License". Thus the license will be copied o this path to deleniate that files within this part of the repo use this license instead. 

