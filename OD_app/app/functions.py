import sqlite3, os, string, random
from passlib.hash import sha256_crypt
import time
from functools import wraps
from flask import g, request, redirect, url_for
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from uuid  import uuid4

noteResistance = "CF626rPKdpFPz8CR"

def login_required(f):
  @wraps(f)
  def decorated_function(*args, **kwargs):

    if request.cookies.get('user') == None:
      return redirect(url_for('login', next=request.url))

    connection = sqlite3.connect("./db/database.db")
    cursor = connection.cursor()
    result = cursor.execute("Select session from Users where login = ?;", (request.cookies.get('user'),))
    received = list(cursor.fetchall())
    connection.commit()
    cursor.close()
    
    #sprawdzenie czy sesja jest taka sama jak ta w bazie danych uzytkownika
    if received != None and request.cookies.get('session') == received[0][0]:
      return f(*args, **kwargs)
    return redirect(url_for('login', next=request.url))
  return decorated_function


def sql(strSQL, param):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  cursor.execute(strSQL, param)
  connection.commit()
  cursor.close()

#zwraca id uzytkownika o username = username
def getUserId(login):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select Id from Users where login = ?;", (login,))
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()
  
  if len(received) != 1:
    return False

  return received[0][0]

def getUsers():
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select login from Users;")
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()
  
  l = []
  for el in received:
    l.append(el[0])
  return l


def getIdOfUserSession(session):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select Id from Users where session = ?;", (session,))
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()
  return received[0][0]


def AddSessionToUser(login, sid):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute(f"Update Users set session = ? where login = ?;", (sid, login,))
  connection.commit()
  cursor.close()
  
def refreshCsrfTokenInDB(csrf):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Delete from TokenCSRF;")
  result = cursor.execute(f"Insert into TokenCSRF(session) values (?);", (csrf,))
  connection.commit()
  cursor.close()

def getActualCsrfToken():
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select session from TokenCSRF;")
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()
  return received[0][0]

def getAllUserInFormat():
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select login from Users;")
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()

  string = ""
  for el in received:
    string += el[0] + ' '

  return string

def formatListToAccuracyString(listOfUsers):
  string = ""
  for el in listOfUsers:
    string += el + ' '
  return string

def getUserNotes(login):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  id = getUserId(login)
  result = cursor.execute(f"Select * from Notes where UserId = ?;", (id,))
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()

  it = 0
  size = len(received)
  r,c = (size, 7)
  notes = [[0 for i in range(c)] for j in range(r)]
  while it < size:
    notes[it][0] = received[it][0] #uuid
    notes[it][1] = getUserName(received[it][1]) #user login
    notes[it][2] = received[it][2] #full content
    notes[it][3] = received[it][2][0:30] #content 0-30 chars
    if len(received[it][2]) > 30:
      notes[it][3] += "..."

    notes[it][4] = received[it][3] #title
    notes[it][5] = received[it][4] #share
    if received[it][5] == '':
      notes[it][6] = "No" #encrypted
    else:
      notes[it][6] = "Yes" #encrypted

    it = it + 1

  return notes


def getUserSharedNotes(login):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  id = getUserId(login)
  result = cursor.execute(f"Select * from Notes where userid != ?;", (id,))
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()

  it = 0
  size = len(received)
  r,c = (size, 7)
  notes = [[0 for i in range(c)] for j in range(r)]
  while it < size:
    tmp = received[it][4].split(' ')
    if (request.cookies.get('user') in tmp) == True:
      notes[it][0] = received[it][0] #uuid
      notes[it][1] = getUserName(received[it][1]) #user login
      notes[it][2] = received[it][2] #full content
      notes[it][3] = received[it][2][0:30] #content 0-30 chars
      if len(received[it][2]) > 30:
        notes[it][3] += "..."

      notes[it][4] = received[it][3] #title
      notes[it][5] = received[it][4] #share
      if received[it][5] == '':
        notes[it][6] = "No" #encrypted
      else:
        notes[it][6] = "Yes" #encrypted

    it = it + 1

  return notes


#zwraca username uzytkownika o id = id
def getUserName(id):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select login from Users where id = ?;", (str(id), ))
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()
  return received[0][0]

def getShareUsers(id):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select share from Notes where id = ?;", (id,))
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()

  users = []
  tmp = received[0][0].split(' ')
  for el in tmp:
    if el != '':
      users.append(el)
  
  #dodanie brakujacych uzytkownikow zeby wyswietlali sie wszyscy
  dict = {}
  outUsers = []
  allUsers = getUsers()
  for el in allUsers:
    if el not in users:
      outUsers.append(el)
  
  dict["1"] = users
  dict["0"] = outUsers

  return dict


def getNote(id):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select * from Notes where id = ?;", (id,))
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()
  
  note = []
  note.append(received[0][0]) #uuid
  note.append(getUserName(received[0][1])) #user login
  note.append(received[0][2]) #full content
  note.append(received[0][3]) #title
  note.append(received[0][4]) #share
  if received[0][5] == '':
    note.append("No") #encrypted
  else:
    note.append("Yes") #encrypted

  return note


def getUsersCount():
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select id from Users;")
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()

  return len(received)


def checkPasswordNote(id, password):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select password, salt from Notes where id = ?;", (id,))
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()
  
  #opoznienie weryfikacji hasla
  time.sleep(2)
  
  if len(received) > 1:
    return False

  hashDB = received[0][0]
  saltDB = received[0][1]

  res = sha256_crypt.using(salt = saltDB).hash(password + noteResistance)
  
  if hashDB == res:
    return True
  return False


def getNoteChances(id):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select chance from Notes where id = ?;", (id,))
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()

  if len(received) != 1:
    return False
  
  return received[0][0]


def getUserChances(login):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select chance from Users where login = ?;", (login,))
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()

  if len(received) != 1:
    return -1 #ta wartosc informuje o braku takiego uzytkownika
  
  return received[0][0]


def checkPasswordStrong(password):
  #przeszukanie listy popularnych hasel
  input = open("./db/simplePasswords.txt")
  simplePasswords = input.read()
  if simplePasswords.find(password) != -1:
    return False
  
  #sprawdzenie wymagan skomplkowanego hasla
  #1 duza litera
  #1 cyfra
  #1 mala litera
  #1 znak specjalny
  #ilosc znakow > 8 znakow
  haveSmallLetter = False
  haveBigLetter = False
  haveNumer = False
  haveSpecialChar = False
  minLength = False
  
  for c in password:
    if c.islower() == True:
      haveSmallLetter = True
    if c.isupper() == True:
      haveBigLetter = True
    if c.isnumeric() == True:
      haveNumer = True
    if not c.isalnum() == True:
      haveSpecialChar = True
  
  if len(password) > 8:
    minLength = True
  
  if haveSpecialChar == True and haveBigLetter == True and haveNumer == True and haveSpecialChar == True and minLength == True:
    return True
  else:
    return False


def checkUserPasword(login, password):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select * from Users where login = ?;", (login,))
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()
  
  #opoznienie weryfikacji hasla
  time.sleep(2)
  
  if len(received) != 1:
    return False

  hashDB = received[0][2]
  saltDB = received[0][3]
  res = sha256_crypt.using(salt = saltDB).hash(password + noteResistance)
  
  if hashDB == res:
    return True
  return False


def checkLoginIsNotAsigment(login):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select login from Users where login = ?;", (login,))
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()

  if len(received) != 0:
    return False
  else:
    return True


def getServerMailName():
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select emial from MailServerConf;")
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()

  if len(received) != 1:
    return False

  return received[0][0]


def getServerMailPass():
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute("Select hash from MailServerConf;")
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()

  if len(received) != 1:
    return False

  return received[0][0]

def getUserMail(user):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute(f"Select email from Users where id = ?;", (getUserId(user),))
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()

  if len(received) != 1:
    return False

  return received[0][0]


def setUserAuthenticationCode(user, code):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute(f"UPDATE Users SET code = ? where id = ?;", (code, getUserId(user),))
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()


def getUserAuthenticationCode(user):
  connection = sqlite3.connect("./db/database.db")
  cursor = connection.cursor()
  result = cursor.execute(f"Select code from Users where id = ?;", (getUserId(user),))
  received = list(cursor.fetchall())
  connection.commit()
  cursor.close()

  if len(received) != 1:
    return False

  return received[0][0]