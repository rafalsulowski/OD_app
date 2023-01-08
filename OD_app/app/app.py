from flask import Flask
from flask import make_response, redirect, request, render_template, session, escape
from requests import Request, post
from uuid  import uuid4
from datetime import datetime
import sqlite3
from passlib.hash import sha256_crypt
import functions as f
import random, os
import bleach
import secrets
from functools import wraps
from flask_mail import Mail, Message
from flask import request, redirect


app = Flask(__name__)
noteResistance = "CF626rPKdpFPz8CR"

   
# configuration of mail
app.config['MAIL_SERVER']='smtp.wp.pl'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = f.getServerMailName()
app.config['MAIL_PASSWORD'] = f.getServerMailPass()
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)



@app.route("/sendMailToUser", methods=["GET", "POST"])
def sendMailToUser():
  if request.method == 'GET':
    return render_template("sendMail.html")
  elif request.method == 'POST':
    username = bleach.clean(request.form.get("username"))
    emial = f.getUserMail(username)
    msg = Message('Hello', sender = f.getServerMailName(), recipients = [emial])
    code = secrets.token_hex(8)
    f.setUserAuthenticationCode(username, code)
    msg.body = f'Hello {username}, your authentication code to reset password is: {code}'
    mail.send(msg)
    return render_template("resetPassword.html", user = username)


@app.route("/resetPassword", methods=["POST"])
def resetPassword():
  if request.method == 'POST':
    username = bleach.clean(request.form.get("username"))
    code = bleach.clean(request.form.get("code"))
    password = bleach.clean(request.form.get("password"))
    password2 = bleach.clean(request.form.get("password2"))
    codeDB = f.getUserAuthenticationCode(username)

    if password == password2:
      if code == codeDB:
        if f.checkPasswordStrong(password) == True:
          newSalt = secrets.token_hex(8)
          encrypt = sha256_crypt.using(salt = newSalt).hash(password + noteResistance)
          f.sql("UPDATE Users SET password = ?, salt = ?, code = '', chance = 3 Where login = ? ;", (encrypt, newSalt, username,))
          return redirect("/login", 302)
    
  return render_template("wrongInputResetPasword.html")




@app.route("/", methods=["GET"])
@f.login_required
def index():
  return render_template("homepage.html", user = request.cookies.get('user'))


@app.route("/newNoteSettings", methods=["GET", "POST"])
@f.login_required
def newNoteSettings():
  if request.method == 'GET':
    users = f.getUsers()
    return render_template("newNoteSetting.html", csrf = f.getActualCsrfToken(), user = request.cookies.get('user'), lenUsers = len(users), users = users)
  elif request.method == 'POST':
    csrf = request.form.get("csrf")
    if csrf != f.getActualCsrfToken():
      csrfToken = str(uuid4())
      f.refreshCsrfTokenInDB(csrfToken)
      response = redirect("/ups", 302, secure=True, httponly=True)
      response.set_cookie("csrf", csrfToken, secure=True, httponly=True)
      return redirect("/ups", 302)

    name = bleach.clean(request.form.get("name"))
    user = f.getUserId(bleach.clean(request.form.get("user")))
    id = str(uuid4())

    encrypt = bleach.clean(request.form.get("encrypt"))
    if encrypt == "1": #notatka ma byc szyfrowana
      password = bleach.clean(request.form.get("notePassword"))

      if f.checkPasswordStrong(password):
        newSalt = secrets.token_hex(8)
        hash = sha256_crypt.using(salt=newSalt).hash(password + noteResistance)
        shareString = bleach.clean(request.form.get("user"))
        f.sql("INSERT INTO Notes (Id, UserId, Content, Name, Share, Password, salt, chance) VALUES (?, ?, '', ?, ?, ?, ?, 3);", (id, user, name, shareString, hash, newSalt,))
        return render_template("newNoteWriting.html", csrf = f.getActualCsrfToken(), id = id)
      else:
        return render_template("wrongPasswordInput.html")


    shareString = ""
    share = bleach.clean(request.form.get("share"))
    if share == "0": #dostepna publicznie
      shareString += f.getAllUserInFormat()
    elif share == "1": #dostepna dla wybranych uzytkownikow
      shareString = ""
      users = f.getUsers()
      usersToShare = []
      for i in range(0, len(users)):
        un = request.form.get("cb" + str(i))
        if un != None:
          usersToShare.append(users[i])
      shareString += f.formatListToAccuracyString(usersToShare)
      shareString += bleach.clean(request.form.get("user")) + ' '
    elif share == "-1": #prywatna
      shareString = ""
      shareString += bleach.clean(request.form.get("user"))
    else:
      return redirect("/ups", 302)

    f.sql("INSERT INTO Notes (Id, UserId, Content, Name, Share, Password, salt, chance) VALUES (?, ?, '', ?, ?, '', '', '');", (id, user, name, shareString,))
    return render_template("newNoteWriting.html", csrf = f.getActualCsrfToken(), id = id)


@app.route("/newNoteWriting", methods=["GET", "POST"])
@f.login_required
def newNoteWriting():
  if request.method == 'GET':
    return render_template("newNoteWriting.html", csrf = f.getActualCsrfToken())
  elif request.method == 'POST':
    csrf = request.form.get("csrf")
    if csrf != f.getActualCsrfToken():
      csrfToken = str(uuid4())
      f.refreshCsrfTokenInDB(csrfToken)
      response = redirect("/ups", 302)
      response.set_cookie("csrf", csrfToken, secure=True, httponly=True)
      return redirect("/ups", 302)
      
    id = bleach.clean(request.form.get("id"))
    md = bleach.clean(request.form.get("markdown",""))

    f.sql("UPDATE Notes SET Content = ? WHERE id = ?;", (md, id,))

    return redirect("/", 302)


@app.route("/showNotes", methods=["GET"])
@f.login_required
def showNotes():
  activeuser = request.cookies.get('user')
  notes = f.getUserNotes(activeuser) #notatki zalogowanego uzytkownika
  notesShared = f.getUserSharedNotes(activeuser) #udospetione notatki dla zalogowanego uzytkownika
  
  for el in notesShared:
    if el[0] != 0 and el[1] != 0 and el[2] != 0 and el[3] != 0 and el[4] != 0 and el[5] != 0:
      notes.append(el)
  return render_template("showNotes.html", csrf = f.getActualCsrfToken(), user = activeuser, lenNotes = len(notes), notes = notes)


@app.route("/noteManage", methods=["POST"])
@f.login_required
def noteManage():
  csrf = request.form.get("csrf")
  if csrf != f.getActualCsrfToken():
    csrfToken = str(uuid4())
    f.refreshCsrfTokenInDB(csrfToken)
    response = redirect("/ups", 302)
    response.set_cookie("csrf", csrfToken, secure=True, httponly=True)
    return redirect("/ups", 302)

  id = bleach.clean(request.form.get("id"))
  note = f.getNote(id)
  su = f.getShareUsers(id)
  sizeIn = len(su["1"])
  sizeOut = len(su["0"])
  return render_template("noteManage.html", csrf = f.getActualCsrfToken(), user = request.cookies.get('user'), note = note, lenIn = sizeIn, lenOut = sizeOut, shareUsers = su)


@app.route("/checkEncryptedNote", methods=["POST"])
@f.login_required
def checkEncryptedNote():
  csrf = request.form.get("csrf")
  if csrf != f.getActualCsrfToken():
    csrfToken = str(uuid4())
    f.refreshCsrfTokenInDB(csrfToken)
    response = redirect("/ups", 302)
    response.set_cookie("csrf", csrfToken, secure=True, httponly=True)
    return redirect("/ups", 302)

  id = bleach.clean(request.form.get("id"))
  isEncrypted = bleach.clean(request.form.get("isEncrypted"))

  if isEncrypted == "Yes":
    chance = f.getNoteChances(id)
    if chance == 0:
      return render_template("/faultNoteDecodeBlocked.html")
    return render_template("/typePassword.html", csrf = f.getActualCsrfToken(), id = id, n = chance)
  else:
    note = f.getNote(id)
    su = f.getShareUsers(id)
    sizeIn = len(su["1"])
    sizeOut = len(su["0"])
    return render_template("noteManage.html", csrf = f.getActualCsrfToken(), user = request.cookies.get('user'), note = note, lenIn = sizeIn, lenOut = sizeOut, shareUsers = su)


@app.route("/decodeNote", methods=["POST"])
@f.login_required
def decodeNote():
  csrf = request.form.get("csrf")
  if csrf != f.getActualCsrfToken():
    csrfToken = str(uuid4())
    f.refreshCsrfTokenInDB(csrfToken)
    response = redirect("/ups", 302)
    response.set_cookie("csrf", csrfToken, secure=True, httponly=True)
    return redirect("/ups", 302)

  id = bleach.clean(request.form.get("id"))
  password = bleach.clean(request.form.get("password"))
    
  if f.checkPasswordNote(id, password) == True:
    f.sql("UPDATE Notes SET Chance = 3 WHERE id = ?;", (id,))
    note = f.getNote(id)
    su = f.getShareUsers(id)
    sizeIn = len(su["1"])
    sizeOut = len(su["0"])
    return render_template("noteManage.html", csrf = f.getActualCsrfToken(), user = request.cookies.get('user'), note = note, lenIn = sizeIn, lenOut = sizeOut, shareUsers = su)
  else:
    chance = f.getNoteChances(id) - 1
    f.sql("UPDATE Notes SET Chance = ? WHERE id = ?;", (chance, id,))
    return render_template("faultNoteDecode.html", csrf = f.getActualCsrfToken(), id = id, n = chance)


@app.route("/deleteNote", methods=["POST"])
@f.login_required
def deleteNote():
  csrf = request.form.get("csrf")
  if csrf != f.getActualCsrfToken():
    csrfToken = str(uuid4())
    f.refreshCsrfTokenInDB(csrfToken)
    response = redirect("/ups", 302)
    response.set_cookie("csrf", csrfToken, secure=True, httponly=True)
    return redirect("/ups", 302)

  id = bleach.clean(request.form.get("id"))
  f.sql("DELETE FROM Notes WHERE id = ?;", (id,))
  return redirect("/showNotes", 302)


@app.route("/ups", methods=["GET"])
def ups():
  f = open("block.txt", 'wa')
  f.write("deny ", request.remote_addr, ";\n")
  f.close()
  return render_template("trap.html")



@app.route("/login", methods=["GET", "POST"])
def login():
  if request.method == 'GET':
    return render_template("login.html")
  elif request.method == 'POST':
    login = bleach.clean(request.form.get("login"))
    password = bleach.clean(request.form.get("password"))

    chance = f.getUserChances(login)
    if chance == 0:
      return render_template("userBlocked.html")
    if chance == -1:
      return render_template("userNotExist.html")


    if f.checkUserPasword(login, password) == True:
      f.sql("UPDATE Users SET Chance = 3 WHERE login = ?;", (login,))
      
      sid = str(uuid4())
      f.AddSessionToUser(login, sid)
      
      csrf = str(uuid4())
      f.refreshCsrfTokenInDB(csrf)
      
      response = redirect("/", code=302)
      response.set_cookie("session", sid, secure=True, httponly=True)
      response.set_cookie("user", str(login), secure=True, httponly=True)
      response.set_cookie("csrf", csrf, secure=True, httponly=True)
      return response
    else:
      chance = f.getUserChances(login) - 1
      f.sql("UPDATE Users SET Chance = ? WHERE login = ?;", (chance, login,))
      return render_template("wrongInputLogin.html", n = chance)



@app.route("/register", methods=["GET", "POST"])
def register():
  if request.method == 'GET':
    return render_template("register.html")
  elif request.method == 'POST':
    login = bleach.clean(request.form.get("login"))
    email = bleach.clean(request.form.get("email"))
    password = bleach.clean(request.form.get("password"))
    password2 = bleach.clean(request.form.get("password2"))
    
    if f.checkLoginIsNotAsigment(login) == True:
      if password == password2:
        if f.checkPasswordStrong(password) == True:
          newSalt = secrets.token_hex(8)
          sid = str(uuid4())
          encrypt = sha256_crypt.using(salt = newSalt).hash(password + noteResistance)
          f.sql("INSERT INTO Users(login, password, salt, chance, email, session) VALUES (?, ?, ?, '3', ?, ?)", (login, encrypt, newSalt, email, sid, ))
          
          csrf = str(uuid4())
          f.refreshCsrfTokenInDB(csrf)
          
          response = redirect("/", code=302)
          response.set_cookie("session", sid, secure=True, httponly=True)
          response.set_cookie("user", login, secure=True, httponly=True)
          response.set_cookie("csrf", csrf, secure=True, httponly=True)
          return response
    
  return render_template("wrongInputRegister.html")


@app.route("/logout", methods=["GET"])
@f.login_required
def logout():
  if request.method == 'GET':
    id = f.getIdOfUserSession(request.cookies.get('session'))
    f.sql("Update Users Set Session = '' Where id = ?;", (id,))

    response = redirect("/logoutPage", 302)
    response.set_cookie("session", '', expires=0, secure=True, httponly=True)
    response.set_cookie("user", '', expires=0, secure=True, httponly=True)
    response.set_cookie("csrf", '', expires=0, secure=True, httponly=True)
    return response


@app.route("/logoutPage", methods=["GET"])
def logoutPage():
  if request.method == 'GET':
    return render_template("logout.html")

if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000, debug="True")

