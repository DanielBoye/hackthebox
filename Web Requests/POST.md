# Q: Obtain a session cookie through a valid login, and then use the cookie with cURL to search for the flag through a JSON POST request to '/search.php'

Our goal is to get a flag in a JSON POST. To do so we have to do a few steps, and the question helps us with that.

## Obtain cookie

First we need to obtain a session cookie through a valid login. We do this with using 

```
curl -X POST -d 'username=admin&password=admin' http://138.68.188.223:30650/ -i
```

Save the PHPSESSID.

## Authenticate cookie

Now we need to authenticate our cookie, so we can use it multiple times. This is so we don't need to put in our username and password each time.
```
curl -b 'PHPSESSID=6ecf455v5l3i33fis58jl2ql2n' http://138.68.188.223:30650/
```

## Find the flag

To find the flag we need to switch the search to "flag" instead of a contry. 

```
curl -X POST -d '{"search":"flag"}' -b 'PHPSESSID=6ecf455v5l3i33fis58jl2ql2n' -H 'Content-Type: application/json' http://138.68.188.223:30650/search.php
```

---

Now you should see your flag
