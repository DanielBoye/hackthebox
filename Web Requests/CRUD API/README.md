# Q: First, try to update any city's name to be 'flag'. Then, delete any city. Once done, search for a city named 'flag' to get the flag.

Our goal is to update a city's name, delete it and just search for "flag" as a country.

## Update a city name

I want to update the city, London. First lets check out if it even exists. 

```
curl -s http://http://138.68.188.223:30650/api.php/city/london | jq 
```
<br>

If it shows you a result like this, you are good to go. 

```
[
  {
    "city_name": "London",
    "country_name": "(UK)"
  }
]
```
<br>

Now to update it we use this command. 

```
curl -X PUT http://139.59.177.61:32007/api.php/city/london -d '{"city_name":"flag"}' -H 'Content-Type: application/json'
```
<br>

Now you have changed the city name to flag, instead of London.

## Delete cites

Now I just want to delete a few cities, so the flag can show up in our "Flag" city. We delete contries over php api's with this command.
```
curl -X DELETE http://139.59.177.61:32007/api.php/city/Oslo
```

```
curl -X DELETE http://139.59.177.61:32007/api.php/city/Leeds
```

```
curl -X DELETE http://139.59.177.61:32007/api.php/city/Birmingham
```
<br>

Now we have deleted a few cities. Time to find our flag and get this challenge done!

## View flag

To view our flag, we need to show our city in read mode. To do that we use the same command we used previously to check if the city London existed.

The only thing we are editing here are the "london", and changing it to "flag" to see our flag.

```
curl -s http://http://138.68.188.223:30650/api.php/city/flag | jq 
```
