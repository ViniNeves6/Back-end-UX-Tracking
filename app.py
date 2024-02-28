from flask_pymongo import pymongo
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    Response,
    flash,
    jsonify,
    session,
    abort,
)
from authlib.integrations.flask_client import OAuth
from authlib.common.security import generate_token
import json
import os
import base64
import re
from flask_mail import Mail, Message
from simple_colors import *
import csv
from pathlib import Path
import pandas as pd
import zipfile
import shutil
import datetime
import random
import string
from dotenv import load_dotenv
from bson import ObjectId
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sys
from unidecode import unidecode
import plotly.io as pio
from io import StringIO
from django.core.paginator import Paginator

# delete se estiver utilizando windows
load_dotenv()
# funções nativas
from functions import (
    id_generator,
    list_dates,
    nlpBertimbau,
    dirs2data,
    make_heatmap,
    make_recording,
    format_ISO,
    graph_sentiment,
)

# conexão com a base
CONNECTION_STRING = os.environ["URI_DATABASE"]
client = pymongo.MongoClient(CONNECTION_STRING)
db = client.get_database("users")

# declarando o servidor
app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

# autenticação google
oauth = OAuth(app)

# configurando o serviço de email
app.config.update(
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME=os.environ["MAIL_NAME"],
    MAIL_PASSWORD=os.environ["MAIL_PASSWORD"],
)
mail = Mail(app)

# Define a rota para a página de registro
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Obtém o usuário e a senha informados no formulário
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")

        # Verifica se o usuário já existe na coleção de usuários
        userfound = db.users.find_one({"email": email})
        if userfound is None:
            # Insere o novo usuário na coleção de usuários
            db.users.insert_one({"username": username, "password": password, "email": email})

            # Cria uma nova coleção para o usuário. Inserimos um documento inicial para garantir que a coleção seja criada.
            user_collection_name = f"user_data_{username}"  # Nomeia a coleção de forma única para o usuário
            db[user_collection_name].insert_one({"message": "Coleção criada para o usuário."})
        else:
            flash("Esse email já foi cadastrado")
            return render_template("register.html", title="Registrar")
        
        # Redireciona para a página de login após o registro bem-sucedido
        return redirect(url_for("login", title="Login"))

    else:
        # Se a requisição for GET, exibe a página de registro
        if "username" in session:
            return redirect(url_for("index"))
        else:
            return render_template("register.html", session=False, title="Registrar")


# Define a rota para a página de login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Obtém o usuário e a senha informados no formulário
        username = request.form["username"]
        password = request.form["password"]
        userfound = db.users.find_one({"username": username, "password": password})

        if userfound != None:
            session["username"] = request.form["username"]
            return redirect(url_for("index"))
        else:
            # Se as credenciais estiverem incorretas, exibe uma mensagem de erro
            flash("Usuário ou senha incorretos.")
            return render_template("login.html", session=False, title="Login")
    else:
        # Se a requisição for GET, exibe a página de login
        if "username" in session:
            return redirect(url_for("index"))
        else:
            return render_template("login.html", session=False, title="Login")

# autenticação google
@app.route('/google/')
def google():

    GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
    GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]

    CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url=CONF_URL,
        client_kwargs={
            'scope': 'openid email profile'
        }
    )

    # Redirect to google_auth function
    redirect_uri = url_for('google_auth', _external=True)
    session['nonce'] = generate_token()
    return oauth.google.authorize_redirect(redirect_uri, nonce=session['nonce'])

@app.route('/google/auth/')
def google_auth():
    token = oauth.google.authorize_access_token()
    user = oauth.google.parse_id_token(token, nonce=session['nonce'])
    username = user['name']
    email = user['email']
    password = user['sub']
    
    # Verifica se o usuário já existe
    userfound = db.users.find_one({"email": email})
    if userfound == None:
        db.users.insert_one(
            {"username": username, "password": password, "email": email, "data": {}}
        )
    session['username'] = username
    return redirect('/')

# Define a rota para o logout
@app.route("/logout")
def logout():
    # remove the username from the session if it's there
    session.pop("username", None)
    return redirect(url_for("index"))


# Define a rota para reset de password
@app.route("/forgot_pass", methods=["GET", "POST"])
def forgot_pass():
    if request.method == "POST":
        # Obtém o usuário e email informados no formulário
        username = request.form["username"]
        email = request.form["email"]
        userfound = db.users.find_one({"username": username, "email": email})

        if userfound != None:
            # Se as credenciais estiverem corretas, envia um email para o usuário
            # com a nova senha criada e redireciona para o login

            # Nova senha gerada
            generatedPass = id_generator()

            # Requisição por email
            msg = Message(
                "UX-Tracking password reset.",
                sender=app.config.get("MAIL_USERNAME"),
                recipients=[email],
            )

            #estilizando a mensagem de e-mail
            msg.html = render_template("email_forgot_pass.html", username= username, generatedPass = generatedPass)

            # Nova senha enviada
            mail.send(msg)

            flash('E-mail enviado com sucesso!')

            # senha alterada
            _id = userfound["_id"]
            db.users.update_one({"_id": _id}, {"$set": {"password": generatedPass}})

            # Redirecionar para o login após o envio do email e atualização da senha
            return redirect(url_for("login", title="Login", session=False))
        
        #Se as credenciais estiverem incorretas, retorna para a página de redefinir senha
        else: 
            flash('Usuário incorreto')
            return render_template('forgot_pass.html', session=False, title='Esqueci a senha')
    else:
        return render_template(
            "forgot_pass.html", session=False, title="Esqueci a senha"
        )


# Define a rota para a página de alteração de senha
@app.route("/change_pass", methods=["POST"])
def change_pass():
    if request.method == "POST":
        if "username" in session:
            # Obtém o usuário e a senha informados no formulário
            username = session["username"]
            password = request.form["password"]
            newpassword = request.form["newpassword"]
            newpassword2 = request.form["confirm_newpassword"]

            # Verifica se as credenciais estão corretas
            userfound = db.users.find_one({"username": username, "password": password})
            if userfound != None:
                if newpassword == newpassword2:
                    idd = userfound["_id"]
                    db.users.update_one(
                        {"_id": idd}, {"$set": {"password": newpassword}}
                    )
                    # Usuário logado
                    return redirect(
                        url_for(
                            "index",
                            session=True,
                            title="Home",
                            username=session["username"],
                        )
                    )

                else:
                    flash(
                        "Verifique se ambas as novas senhas são iguais e tente novamente!"
                    )
                    return render_template("index.html", session=True, title="Home")
            else:
                flash("A senha atual está incorreta!")
                return render_template("index.html", session=True, title="Home")

        else:
            flash("Faça o login!")
            return render_template("login.html", session=False, title="Login")


# Define a rota para a página principal
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if "username" in session:
            # faz a leitura da base de dados de coletas do usuário
            userfound = db.users.find_one({"username": session["username"]})
            userid = userfound["_id"]
            datadir = f"./Samples/{userid}"

            folder = request.form.getlist("dates[]")
            folder = folder[0]

            #normalizando o caminho base
            base_path = os.path.normpath(datadir)

            #normalizando o caminho completo
            fullpath = os.path.normpath(os.path.join(base_path, folder))

            #verificando se o caminho completo começa com o caminho base
            if not fullpath.startswith(base_path):
                raise Exception("not allowed")

            # cria um zip para inserção dos dados selecionados
            with zipfile.ZipFile(f"{folder}_data.zip", "w") as zipf:
                for file in os.listdir(fullpath): 
                    shutil.copy(os.path.join(fullpath, file), file)
                    zipf.write(file)
                    os.remove(file)

            # limpando o zip criado
            with open(f"{folder}_data.zip", "rb") as f:
                data = f.readlines()
            os.remove(f"{folder}_data.zip")

            # fornecendo o zip pra download
            return Response(
                data,
                headers={
                    "Content-Type": "application/zip",
                    "Content-Disposition": f"attachment; filename={folder}_data.zip;",
                },
            )

        else:
            return render_template("index.html", session=False, title="Home")
    else:
        if "username" in session:
            # faz a leitura da base de dados de coletas do usuário
            userfound = db.users.find_one({"username": session["username"]})
            userid = userfound["_id"]
            datadir = f"./Samples/{userid}"

            # verifica quais datas estão disponíveis e limpa a string
            dates = []
            folder = []
            figdata = {}
            i = 0

            #pegar o nome dos arquivos
            for pasta in userfound["data"]:
                if pasta in os.listdir(datadir):
                    folder.append(pasta)

            folder_reverse = folder[::-1]

            try:
                for folder in userfound["data"]:
                    # print(folder)
                    date = userfound["data"][folder]["date"]         
                    if date not in figdata.keys():
                        figdata[date] = 1
                    else:
                        figdata[date] += 1
                    if i <= 4:
                        date_info = userfound["data"][folder_reverse[i]]
                        dates.append(
                            [
                                date_info["date"],
                                date_info["hour"],
                                date_info["sites"],
                                folder_reverse[i],
                            ]
                        )
                        i += 1

            except:
                None

            datas = format_ISO(figdata.keys())
            values = list(figdata.values())

            # lista de coletas
            return render_template(
                "index.html",
                session=True,
                username=session["username"],
                title="Home",
                dates=dates,
                datas=datas,
                values=values
            )
        else:
            return render_template("index.html", session=False, title="Home")

@app.route("/datafilter/<username>/<metadata>", methods=["GET", "POST"])
def datafilter(username, metadata):
    if request.method == "POST" and "username" in session:
        # Verifica se o nome de usuário na sessão corresponde ao nome de usuário na URL
        if session["username"] != username:
            flash("Acesso negado: usuário não corresponde.")
            return redirect(url_for("login"))

        user_collection_name = f"{username}_data"

        if metadata == "datetime":
            session["dates"] = request.form.getlist("dates[]")
            return redirect(url_for("datafilter", username=username, metadata="pages"))

        elif metadata == "pages":
            session["pages"] = request.form.getlist("pages[]")

            tracefiltered = pd.DataFrame(columns=[
                "datetime", "site", "type", "time", "image", "class", "id",
                "mouseClass", "mouseId", "x", "y", "keys", "scroll", "height",
            ])
            audiofiltered = pd.DataFrame(columns=[
                "site", "time", "text", "image", "class", "id", "mouseClass",
                "mouseId", "x", "y", "scroll", "height",
            ])

            datadir = f"./Samples/{username}"  # Ajuste o caminho conforme a estrutura de diretórios

            for date in session["dates"]:
                try:
                    df_trace = pd.read_csv(f"{datadir}/{date}/trace.csv")
                    df_trace = df_trace[df_trace['site'].isin(session["pages"])]
                    df_trace["datetime"] = date
                    tracefiltered = pd.concat([tracefiltered, df_trace], ignore_index=True)

                    df_audio = pd.read_csv(f"{datadir}/{date}/audio.csv")
                    df_audio = df_audio[df_audio['site'].isin(session["pages"])]
                    df_audio["datetime"] = date
                    audiofiltered = pd.concat([audiofiltered, df_audio], ignore_index=True)
                except FileNotFoundError:
                    # Se o arquivo não for encontrado, continue para o próximo arquivo
                    continue

            # Insere os dados acumulados na coleção específica do usuário
            if not tracefiltered.empty:
                db[user_collection_name].insert_many(tracefiltered.to_dict('records'))
            if not audiofiltered.empty:
                db[user_collection_name].insert_many(audiofiltered.to_dict('records'))

            flash("Dados processados e inseridos com sucesso.")
            return redirect(url_for("index", username=username))

        else:
            flash("404\nPage not found!")
            return render_template("data_filter.html", username=username, title="Coletas")

    else:
        # Tratamento para GET ou usuário não logado
        return render_template("index.html", session="username" in session)

if __name__ == "__main__":
    app.run(debug=True)


@app.route("/dataanalysis/<username>/", methods=["GET", "POST"])
@app.route("/dataanalysis/<username>/<model>", methods=["GET", "POST"])
def dataanalysis(username, model=None):
    if request.method == "POST":
        if "username" in session and session["username"] == username:
            # Acessando a coleção específica do usuário no MongoDB
            user_collection_name = f"{username}_data"
            user_collection = db[user_collection_name]

            if model == "kmeans":
                
                return
            elif model == "meanshift":
                
                return
            elif model == "bertimbau":
                results = {}
                try:
                    # Exemplo: Buscar dados de áudio específicos para análise
                    audio_data = user_collection.find({"type": "audio"})
                    # Supondo que nlpBertimbau possa aceitar dados diretamente do MongoDB (qualquer coisa, irei trocar)
                    df_audio = nlpBertimbau(audio_data)
                    fig = graph_sentiment(df_audio)
                    results['result1'] = json.dumps(fig)  # Certificar que a fig pode ser serializado para JSON
                    results['result2'] = True
                except Exception as e:
                    results['result1'] = "Não foi possível processar a coleta, áudio ausente!"
                    results['result2'] = False
                return results
            else:
                flash("Modelo de análise não encontrado.")
                return render_template("data_analysis.html", username=username, title="Análise")
        else:
            flash("Por favor, faça o login para continuar.")
            return redirect(url_for("login"))

    # método GET ou usuário não logado
    else:
        if "username" in session and session["username"] == username:
            # Aqui, você poderia listar os modelos disponíveis ou outra lógica inicial
            return render_template("data_analysis.html", username=username, title="Análise")
        else:
            flash("Faça o login para continuar.")
            return redirect(url_for("login"))

@app.route("/downloadAudio", methods=['POST'])
def downloadAudio():
    # Encontrando o usuário logado e preparando o nome da coleção
    username = session.get("username")
    if not username:
        flash("Usuário não está logado.")
        return redirect(url_for("login"))

    # Preparando a query para buscar os dados de áudio
    valueData = request.form.get("data")  
    audio_data_cursor = db[f"{username}_audio_collection"].find({"datetime": valueData})

    # Convertendo os dados do cursor para DataFrame
    audio_data_df = pd.DataFrame(list(audio_data_cursor))

    # Removendo a coluna do ObjectId gerado pelo MongoDB
    if "_id" in audio_data_df.columns:
        audio_data_df.drop(columns=["_id"], inplace=True)

    # Criando um buffer de string para armazenar o CSV
    str_io = StringIO()
    audio_data_df.to_csv(str_io, index=False)
    str_io.seek(0)  # Movendo para o início do buffer para garantir a leitura completa

    # Retornando os dados como um arquivo CSV
    return Response(
        str_io.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=audio_{valueData}.csv"}
    )

@app.route("/dataview/<username>/", methods=["GET", "POST"])
@app.route("/dataview/<username>/<plot>", methods=["GET", "POST"])
def dataview(username, plot=None):
    if "username" in session and session["username"] == username:
        # Acesso à coleção do usuário específico no MongoDB
        user_collection = db[f"{username}_collection"]

        if request.method == "POST":
            dir = request.form.get("dir")  

            if plot == "heatmap":
                
                ######################Talvez a função 'make_heatmap e 'make_recording' precisaria ser ajustada para trabalhar com dados do MongoDB#####################################
                data = user_collection.find({"dir": dir})
                return make_heatmap(data)
            elif plot == "recording":
                data = user_collection.find({"dir": dir})
                return make_recording(data, type="mouse")
            elif plot == "nlp":
                return 
            else:
                flash("Visualização não encontrada.", "error")
                return redirect(url_for("index"))

        else:  # Método GET
           
            return render_template("data_view_selection.html", username=username, plots=["heatmap", "recording", "nlp"])

    else:
        flash("Por favor, faça o login para continuar.", "info")
        return redirect(url_for("login"))

@app.route("/external/", methods=["POST"])
@app.route("/external/userAuth", methods=["POST"])
def userAuth():
    username = request.form.get("username")
    password = request.form.get("password")

    # Busca por um usuário que corresponda ao nome de usuário e senha fornecidos
    userfound = db.users.find_one({"username": username, "password": password})

    if userfound:
        # Armazenando o nome de usuário na sessão para manter o estado do login
        session["username"] = username
        # Retornando o ID do usuário e status de sucesso
        response = {"id": str(userfound["_id"]), 'status': 200}
    else:
        # Caso as credenciais estejam incorretas, não armazena nada na sessão
        # e retorna uma resposta indicando falha na autenticação
        response = {"id": None, 'status': 401}

    return jsonify(response)

@app.route("/external/userRegister", methods=["POST"])
def userRegister():
    username = request.form["username"]
    password = request.form["password"]
    email = request.form["email"]

    # Verifica se o usuário já existe
    userfound = db.users.find_one({"$or": [{"email": email}, {"username": username}]})
    if userfound == None:
        db.users.insert_one(
            {"username": username, "password": password, "email": email, "data": {}}
        )
        userfound = db.users.find_one({"username": username, "password": password})
        response = {"id": str(userfound["_id"]), 'status': 200}
    else:
        response = {"id": None, 'status': 401}
        
    return jsonify(response)

@app.route("/external/userRecover", methods=["POST"])
def userRecover():
    email = request.form["email"]
    user_collection = db['users']  # A coleção que contém os usuários
    userfound = user_collection.find_one({"email": email})

    if userfound:
        # Geração de nova senha
        generatedPass = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

        # Configuração e envio do email
        msg = Message("Password Reset Request",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f"Your new password is: {generatedPass}"
       
        mail.send(msg)

        # Atualização da senha no banco de dados
        user_collection.update_one({"_id": userfound["_id"]}, {"$set": {"password": generatedPass}})

        return jsonify({'status': 'success', 'message': 'Password reset successfully. Please check your email.'}), 200
    else:
        return jsonify({'status': 'failure', 'message': 'Email not found.'}), 404

# Define a rota para o envio dos dados pela ferramenta
# Organização do patch:
# (Diretório de samples)/(ID do usuário, gerado pela função generate_user_id em functions.py)/(YYYYMMDD-HHMMSS da coleta)/(dados da coleta)
@app.route("/external/receiver", methods=["POST"])
def receiver():
    metadata = json.loads(request.form["metadata"])
    data = json.loads(request.form["data"])
    userid = metadata["userId"]

    # Busca pelo usuário usando o ObjectId para garantir que o usuário existe
    userfound = db.users.find_one({"_id": ObjectId(userid)})
    if not userfound:
        return "ERROR: Usuário não autenticado", 401

    # Prepara o nome da coleção baseado no nome do usuário
    user_collection_name = f"{userfound['username']}_data"

    # Prepara o documento com os dados recebidos
    document = {
        "dateTime": metadata["dateTime"],
        "date": f"{metadata['dateTime'][6:8]}/{metadata['dateTime'][4:6]}/{metadata['dateTime'][0:4]}",
        "hour": f"{metadata['dateTime'][9:11]}:{metadata['dateTime'][11:13]}:{metadata['dateTime'][13:15]}",
        "type": metadata["type"],
        "site": metadata.get("sample"),
        "time": metadata["time"],
        "imageName": data.get("imageName"),
        # Inclui mais campos conforme necessário
    }

    # Adiciona campos específicos com base no tipo de dados recebidos
    if metadata["type"] in ["eye", "mouse", "keyboard", "freeze", "click", "wheel", "move"]:
        document.update({
            "class": data.get("Class"),
            "id": data.get("Id"),
            "mouseClass": data.get("mouseClass"),
            "mouseId": data.get("mouseId"),
            "x": data.get("X"),
            "y": data.get("Y"),
            "keys": data.get("Typed"),
            "scroll": metadata.get("scroll"),
            "height": metadata.get("height"),
            # Adiciona outros campos conforme necessário
        })

    # Caso especial para dados de imagem
    if "imageData" in data and data["imageData"] != "NO":
        imageData = base64.b64decode(data["imageData"].split(",")[1])
        # Aqui, você pode optar por salvar a imagem de outra forma, como em um sistema de arquivos ou banco de dados de objetos

    # Insere o documento na coleção do MongoDB
    db[user_collection_name].insert_one(document)

    return "Data received and inserted successfully", 200


# Define a rota para o envio dos dados pela ferramenta
# Organização do patch:
# (Diretório de samples)/(ID do usuário, gerado pela função generate_user_id em functions.py)/(data+hora da coleta)/(dados da coleta)
def sample_checker():
    if request.method == "POST":
        dateTime = request.form["dateTime"]
        username = request.form["username"]  # Supondo que o nome de usuário seja passado no request
        user_collection_name = f"{username}_data"

        # Procura pela amostra mais recente baseada no dateTime fornecido
        latest_sample = db[user_collection_name].find_one(
            {"dateTime": {"$lte": dateTime}},
            sort=[("dateTime", -1)]
        )

        if latest_sample:
            # Retorna o dateTime da última amostra encontrada
            return latest_sample["dateTime"]
        else:
            # Caso não encontre uma amostra, retorna "0"
            return "0"

def send_email(subject, body):
    # Configurar as informações de email
    sender_email = app.config.get("MAIL_USERNAME")
    sender_password = app.config.get("MAIL_PASSWORD")
    receiver_email = 'flavio.moura@itec.ufpa.br'

    # Criar o objeto de mensagem
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = subject

    # Adicionar o corpo da mensagem
    message.attach(MIMEText(body, 'plain'))

    # Enviar o email usando SMTP
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, receiver_email, message.as_string())
    server.quit()

if __name__ == "__main__":
    try:
        app.run(debug=False, host="0.0.0.0")
    except BaseException as e:
        dt = datetime.datetime.today()
        dt = f'{dt.day}/{dt.month}/{dt.year}'
        error_context = sys.exc_info()[1].__context__.strerror
        error_context = unidecode(error_context)
        error_msg = f'The application failed to start in {dt}.\r The message of error is: {sys.exc_info()[0]}:{e} - {error_context}'
        send_email("UX-Tracking Initialization Failed.", error_msg)
