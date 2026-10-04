metadata.jwt.gz: metadata.jwt
	gzip metadata.jwt

metadata.jwt:
	curl -f https://mds.fidoalliance.org -o metadata.jwt

clean:
	rm -rf metadata.jwt.gz
