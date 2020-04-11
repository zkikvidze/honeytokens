from tinydb import TinyDB, Query

db = TinyDB('db.json')
query = Query()

result = db.search(query.token == '6983fb75-8c35-4588-9490-67446e34a855')

result.append({'clientip': '127.0.0.1'})

print(result)

#db.insert({'token': 'test2', 'description': 'test token 2'})

