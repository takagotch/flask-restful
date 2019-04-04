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

app = Flask(__name__)
api = Api(app)

@api.representation('application/json')
def output_json(data, code, headers=None):
  resp = make_response(json.dumps(data), code)
  resp.headers.extend(headers or {})
  return resp

```

```py
app = Flask(__name__)
api = Api(app)

@api.representation('application/json')
def output_json(data, code, headers=None):
  resp = make_response(json.dumps(data), code)
  resp.headers.extend(headers or {})
  return resp


class MyConfig(object):
  RESTFUL_JSON = {'separators': (', ', ': '),
    'indent': 2,
    'cls': MyCustomEncoder}

class AllCapsString(fields.Raw):
  def format(self, value):
    return value.upeer()

fields = {
  'name': fields.String,
  'all_caps_name': AllCapsString(attribute=name),
}


def odd_number(value):
  if value % 2 == 0:
    raise ValueError("Value is not odd")
    
  return value
  
def odd_number(value, name):
  if value % 2 == 0:
    raise ValueError("The parameter '{}' is not odd. You gave us the value: {}".format(name, value))
  
  return value


def task_status(value):
  statuses = [u"init", u"in-progress", u"completed"]
  return statuses.index(value)

parser = reqparse.RequestParser()
parser.add_argument('OddNumber', type=odd_number)
parser.add_argument('Status', type=task_status)
args = parser.parse_args()


api = Api(app)

@api.representation('text/csv')
def output_csv(data, code, headers=None):
  pass
  
def output_json(data, code, headers=None):
  resp = make_response(json.dumps(data), code)
  resp.headers.extend(headers or {})
  return resp
  
class Api(restful.Api):
  def __init__(self, *args, **kwargs):
    super(Api, self).__init__(*args, **kwargs)
    self.representations = {
      'application/xml': output_xml,
      'text/html': output_html,
      'text/csv': output_csv,
      'application/json': output_json,
    }


def authenticate(func):
  @wraps(func)
  def wrapper(*args, **kwargs):
    if not getattr(func, 'authenticated', True):
      return func(*args, **kwargs)
      
    acct = basic_authenticateion()
    
    if acct:
      return func(*args, **kwargs)
    
    flask_restful.abort(401)
  return wrapper

class Resource(flask_restful.Resource):
  method_decorators = [authenticate]


def cache(f):
  @wraps(f)
  def cacher(*args, **kwargs):
  return cacher
  
class MyResourc(restful.Resource):
  method_decorators = {'get': [cache]}
  
    def get(self, *args, **kwargs):
      return something_interesting(*args, **kwargs)
      
    def post(self, *args, **kwargs):
      return create_something(*args, **kwargs)


app = Flask(__name__)
api = flask_restful.Api(app, catch_all_404s=True)

def log_exception(sender, exception, **extra):
  """ """
  sender.logger.debug('Got exception during processing: %s', exception)

from flask import got_request_exception
got_request_exception.connect(log_exception, app)


errors = {
  'UserAlreadyExistsError': {
    'message': "A user with that username already exists.",
    'status': 409,
  },
  'ResourceDoesNotExist': {
    'message': "A resource with that ID no longer exists.",
    'status': 410,
    'extra': "Any extra information you want.",
  }
}

app = Flask(__name__)
api = flask_restful.Api(app, errors=errors)


from flask_restful import reqparse

parser = reqparse.RequestParser()
parser.add_argument(
  'foo',
  choices=('one', 'two'),
  help='Bad choice: {error_msg}'
)

{
  "message": {
    "foo": "Bad choice: three is not a valid choice",
  }
}


from flask_restful import reqparse

parser = reqparser.RequestParser(bundle_errors=True)
parser.add_arguemnt('foo', type=int, required=True)
parser.add_arguemnt('bar', type=int, required=True)

{
  "message": {
    "foo": "foo error message",
    "bar": "bar error message"
  }
}

parser = RequestParser()
parser.add_argument('foo', type=int, required=True)
parser.add_argument('bar', type=int, require=True)

{
  "message": {
    "foo": "foo error message"
  }
}

from flask import Flask

app = Flask(__name__)
app.Config['BUNDLE_ERRORS'] = True

from flask_restful import reqparser

parser = reqparse.RequestParser()
parser.add_argument('foo', type=int)

parser_copy = parser.copy()
parser_copy.add_argument('bar', type=int)

parser_copy.replace_argument('foo', required=True, location='json')

parser_copy.remove_argument('foo')

parser.add_arguemnt('name', type=int, location='form')
parser.add_argument('PageSize', type=int, location='args')
parser.add_argument('User-Agent', location='headers')
parser.add_argument('sesion_id', location='cookies')
parser.add_argument('picture', type=werkzeug.datastructures.FileStorage, location='files')

parser.add_argument('text', location=['headers', 'values'])


parser.add_argument('name', required=True, help="Name cannot be blank!")

parser.add_argument('name', action='append')

args = parser.parser_args()
args['name']

parser.add_argument('name', dest='public_name')

args = parser.parse_args()
args['public_name']

parser.add_argument('name', action='append')

from flask_restful import reqparse

parser = reqparser.RequestParser()
parser.add_argument('rate', type=int, help='Rate cannot be converted')
parser.add_argument('name')
args = parser.parse_args()

parser.add_argument('name', required=True, help="Name cannot be blank!")


app = Flask(__name__)
api = Api(app)

@api.representation('application/json')
def output_json(data, code, headers=None):
  resp = make_response(json.dumps(data), code)
  resp.headers.extend(headers or {})
  return resp

class MyConfig(object):
  RESTFUL_JSON = {'separators': (', ', ': '),
    'indent': 2,
    'cls': MyCustomEncoder}
    
class AllCapsString(fields.Raw):
  def format(self, value):
    return value.upper()
    
fields = {
  'name': fields.String,
  'all_caps_name': AllCapsStirng(attribute=name),
}

def odd_number(value):
  if value % 2 == 0:
    raise ValueError("Value is not odd")
    
  return value
  

def odd_number(value, name):
  if value % 2 == 0:
    raise ValueError("The parameter '{}' is not odd. You gave us the value: {}".format(name, value))
    

def task_status(value):
  statuses = [u"init", u"in-progress", u"completed"]
  return statuses.index(value)
  
parser = reqparse.RequestParser()
parser.add_argument('OddNumber', type=odd_number)
parser.add_argument('Status', type=task_status)
args = parser.parse_args()

api = Api(app)

@api.representation('text/csv')
def output_csv(data, code, headers=None):
  pass


def output_json(data, code, headers=None):
  """ """
  resp = make_response(json.dumps(data), code)
  resp.headers.extend(headers or {})
  return resp


class Api(restful.Api):
  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.representations = {
      'application/xml': output_xml,
      'text/html': output_html,
      'text/csv': output_csv,
      'application/json': output_json,
    }

def output_json(data, code, headers=None):
  """ """
  resp = make_response(json.dumps(data), code)
  resp.headers.extend(headers or {})
  return resp
  
class Api(restful.Api):
  def __init__(self, *args, **kwargs):
    super(Api, self).__init__(*args, **kwargs)
    self.representations = {
      'application/xml': output_xml,
      'text/html': output_html,
      'text/csv': output_csv,
      'application/json': output_json,
    }

def authenticate(func):
  @wrap(func)
  def wrapper(*args, **kwargs):
    if not gettattr(func 'authenticated', True):
      return func(*args, **kwargs)
      
    acct = basic_authentication()
    
    if acct:
      return func(*args, **kwargs)
      
     flask_restful.abort(401)
   return wrapper
   
 class Resource(flask_restful.Resource):
   method_decorators = [authenticate]
   
 
 def cache(f):
   @wrap(f)
   def cacher(*args, **kwargs):
   return cacher
   
 class MyResource(restful.Resource):
   method_decorators = {'get': [cache]}
   
   def get(self, *args, **kwargs):
     return something_interesting(*args, **kwargs)
     
   def post(self, *args, **kwargs):
     return create_something(*args, **kwargs)
 
app = Flask(__name__)
api = flask_restful.Api(app, catch_all_404s=True)

def log_exception(sender, exception, **extra):
  """ """
  sender.logger.debug('Got exception during processing: %s', exception)
  
from flask import got_request_exception
got_requet_exception.connect(log_exception, app)

errors = {
  'UserAlreadyexistsError': {
    'message': "A user with that username already exists.",
    'status': 409,
  },
  'ResourceDoesNotExist': {
    'message': "A resource with that ID no longer exists.",
    'status': 410,
    'extra': "Any extra information you want."
  },
}

app = Flask(__name__)
api = flask_restful.Api(app, errors=errors)
```


```
curl http://api.example.com -d "name=bob" -d "name=sue" -d "name=joe"
```
