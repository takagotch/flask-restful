### flask-restful
---
https://github.com/flask-restful/flask-restful

https://flask-restful.readthedocs.io/en/latest/

```py
from flask import Flask
from flask_restful import reqparse, abort, Api, Resource

app = Flask(__name__)
api = Api(app)

TODOS = {
  'todo1': {'task': 'build an API'},
  'todo2': {'task': '?????'},
  'todo3': {'task': 'profit!'},
}

def abort_if_todo_doesnt_exist(todo_id):
  if todo_id not in TODOS:
    abort(404, message="Todo {} doesn't exist".format(todo_id))

parser = reqparse.RequestParser()
parser.add_argument('task')

class Todo(Resource):
  def get(self, todo_id):
    abort_if_todo_doesnt_exist(todo_id)
    return TODOS[todo_id]
  
  def delete(self, todo_id):
    abort_if_todo_doesnt_exist(todo_id)
    del TODOS[todo_id]
    return '', 204
  
  def put(self, todo_id):
    args = parser.parse_args()
    task = {'task': args['task']}
    TODOS[todo_id] = task
    return task, 201
  
class TodoList(Resource):
  def get(self):
    return TODOS
    
  def post(self):
    args = parser.parse_args()
    todo_id = int(max(TODOS.keys()).lstrip('todo')) + 1
    todo_id = 'todo%i' % todo_id
    TODOS[todo_id] = {'task': args['task']}
    return TODOS[todo_is], 201
    
api.add_resource(TodoList, '/todos')
api.add_resource(Todo, '/todos/<todo_id>')

if __name__ == '__main__':
  app.run(debug=True)
```

```py
from flask_restful import Resource, fields, marshal_with

resource_fields = {
  'name': fields.String,
  'address': fields.String,
  'date_updated': fields.DateTime(dt_format='rfc822').
}

class Todo(Resource):
  @marshal_with(resource_fields, envelop='resource')
  def get(self, **kwargs):
    return db_get_todo()

class RandomNuber(fields.Raw):
  def output(self,key, obj):
    return random.random()
    
fields = {
  'name': fileds.Stirng,
  'uri': fields.Url('todo_resource'),
  'random': RandomNumber,
}
```

```
```


