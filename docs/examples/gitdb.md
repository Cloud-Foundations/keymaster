# gitdb

A database for user and group information using Git as the back-end.

The database is read from `groups.json` files in directories in the repository.
All the groups files are merged together; the directory structure is not
relevant to how the repository is processed. This allows for arbitrary directory
structures to reflect the organisation. Each directory must have the following
files:
- `groups.json`: containing group definitions and their memberships
- `permitted-groups.json`: containing a list of regular expressions for the
                           permitted groups in the `groups.json` file

See examples and testdata [here](https://github.com/Cloud-Foundations/golib/tree/master/pkg/auth/userinfo/gitdb)
