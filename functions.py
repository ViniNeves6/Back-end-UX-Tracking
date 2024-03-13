import hashlib
import json
import string
import random
import pandas as pd
import io
import os
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from sklearn.cluster import KMeans, MeanShift, estimate_bandwidth
from matplotlib import pyplot as plt
import cv2 as cv
import numpy as np
import plotly.graph_objects as go
from PIL import Image
import base64
from stitching import Stitcher
from datetime import datetime
import plotly.express as px
from plotly.subplots import make_subplots
from flask import Response
from scipy.ndimage import gaussian_filter
from io import BytesIO
from flask import Flask
from flask_pymongo import PyMongo
from pymongo import MongoClient

folderBert = "bertimbau-finetuned"

client = MongoClient(os.environ["URI_DATABASE"])
db = client["Users"]


tokenizer = AutoTokenizer.from_pretrained(folderBert)
modelBert = AutoModelForSequenceClassification.from_pretrained(folderBert)

id2label = {
    0: "RAIVA",
    1: "MEDO",
    2: "TRISTEZA",
    3: "SURPRESA",
    4: "ALEGRIA",
    5: "NOJO",
}


def format_ISO(dates):
    iso_format_dates = []

    for date in dates:
        date_obj = datetime.strptime(date, "%d/%m/%Y")
        iso_date = date_obj.strftime("%Y-%m-%d")
        iso_format_dates.append(iso_date)

    return iso_format_dates


def nlpBertimbau(username):
    # Recupera os dados de áudio da coleção específica do usuário
    user_collection = db[f"{username}_audio_collection"]
    audio_data = user_collection.find({})  # Você pode ajustar este filtro conforme necessário

    # Converte os dados do cursor para DataFrame
    df_audio = pd.DataFrame(list(audio_data))

    texts = []
    sentiment_dict = {sentiment: [] for sentiment in id2label.values()}
    for text in df_audio["text"]:
        inputs = tokenizer(text, return_tensors="pt")
        with torch.no_grad():
            logits = modelBert(**inputs).logits

        normalize = lambda x, vec: 100 * (x - vec.min()) / (vec.max() - vec.min())
        normalized_logits = [normalize(element, logits) for element in logits]
        output = id2label[normalized_logits[0].argmax().item()]
        for i in range(0, len(normalized_logits[0])):
            sentiment_current = id2label[i]
            sentiment_dict[sentiment_current].append(
                round(normalized_logits[0][i].item(), 4)
            )
        texts.append(output)

    df_audio["feeling"] = texts
    for value in id2label.values():
        df_audio[value.lower()] = sentiment_dict[value]

    return df_audio


def graph_sentiment(df):
    # contagem dos sentimentos para grafico radar
    audio_sentiment = list(df["feeling"])

    sentiment_count = {sentiment: 0 for sentiment in id2label.values()}

    for sentiment in audio_sentiment:
        if sentiment in id2label.values():
            sentiment_count[sentiment] += 1

    # criação de datafrime para grafico radar
    df_radar = pd.DataFrame(
        dict(
            Emoção=list(sentiment_count.keys()), Contagem=list(sentiment_count.values())
        )
    )

    # informações para gráfico dos sentimentos
    df_sentiment = pd.DataFrame(
        dict(
            time=list(df["time"]),
            raiva=list(df["raiva"]),
            medo=list(df["medo"]),
            tristeza=list(df["tristeza"]),
            surpresa=list(df["surpresa"]),
            alegria=list(df["alegria"]),
            nojo=list(df["nojo"]),
        )
    )

    # transformando para string
    df_sentiment["time"] = df_sentiment["time"].astype(str)

    # organização de subplots
    fig = make_subplots(
        rows=4,
        cols=2,
        column_widths=[0.5, 0.5],
        row_heights=[0.56, 0.13, 0.13, 0.13],
        specs=[
            [{"type": "scatterpolar", "colspan": 2}, None],
            [{"type": "bar"}, {"type": "bar"}],
            [{"type": "bar"}, {"type": "bar"}],
            [{"type": "bar"}, {"type": "bar"}],
        ],
        subplot_titles=(
            "Sentiment Dominance Chart",
            "Raiva",
            "Tristeza",
            "Alegria",
            "Surpresa",
            "Nojo",
            "Medo",
        ),
        print_grid=False,
        horizontal_spacing=0.05,
        vertical_spacing=0.08,
    )

    fig.add_trace(
        go.Scatterpolar(
            r=df_radar["Contagem"],
            theta=df_radar["Emoção"],
            fill="toself",
            customdata=df_radar["Emoção"],
            hovertemplate="Sentimento: %{theta} <br>Quantidade: %{r}",
            showlegend=False,
        ),
        row=1,
        col=1,
    )

    fig.add_trace(
        go.Bar(
            x=df_sentiment["time"],
            y=df_sentiment["raiva"],
            marker=dict(color="crimson"),
            showlegend=False,
            name="raiva",
            hovertemplate="Confiança: %{y} <br>Tempo: %{x}",
        ),
        row=2,
        col=1,
    )

    fig.add_trace(
        go.Bar(
            x=df_sentiment["time"],
            y=df_sentiment["tristeza"],
            marker=dict(color="blue"),
            showlegend=False,
            name="tristeza",
            hovertemplate="Confiança: %{y} <br>Tempo: %{x}",
        ),
        row=2,
        col=2,
    )

    fig.add_trace(
        go.Bar(
            x=df_sentiment["time"],
            y=df_sentiment["alegria"],
            marker=dict(color="#FFFF00"),
            showlegend=False,
            name="alegria",
            hovertemplate="Confiança: %{y} <br>Tempo: %{x}",
        ),
        row=3,
        col=1,
    )

    fig.add_trace(
        go.Bar(
            x=df_sentiment["time"],
            y=df_sentiment["surpresa"],
            marker=dict(color="#EEEE33"),
            showlegend=False,
            name="surpresa",
            hovertemplate="Confiança: %{y} <br>Tempo: %{x}",
        ),
        row=3,
        col=2,
    )

    fig.add_trace(
        go.Bar(
            x=df_sentiment["time"],
            y=df_sentiment["nojo"],
            marker=dict(color="#008000"),
            showlegend=False,
            name="nojo",
            hovertemplate="Confiança: %{y} <br>Tempo: %{x}",
        ),
        row=4,
        col=1,
    )

    fig.add_trace(
        go.Bar(
            x=df_sentiment["time"],
            y=df_sentiment["medo"],
            marker=dict(color="#800080"),
            showlegend=False,
            name="medo",
            hovertemplate="Confiança: %{y} <br>Tempo: %{x}",
        ),
        row=4,
        col=2,
    )

    # Update xaxis properties
    fig.update_yaxes(title_text="Confiança", row=2, col=1)
    fig.update_yaxes(title_text="Confiança", row=3, col=1)
    fig.update_yaxes(title_text="Confiança", row=4, col=1)

    # Update yaxis properties
    fig.update_xaxes(title_text="Tempo(s)", row=4, col=1)
    fig.update_xaxes(title_text="Tempo(s)", row=4, col=2)

    fig.update_polars(
        bgcolor="rgba(0, 0, 0, 0)",
    )
    fig.update_yaxes(range=[0, 100])
    fig.update_layout(
        margin=dict(r=60, t=60, b=40, l=60),
        height=1200,
        paper_bgcolor="rgba(33, 37, 41, 1)",
        plot_bgcolor="rgba(0, 0, 0, 0)",
        polar=dict(radialaxis=dict(angle=90, tickangle=90)),
        font=dict(color="white"),
    )
    fig.update_annotations(yshift=15, font=dict(family="Helvetica", size=20))
    return fig


def model_kmeans(data, n_clusters, n_init, max_iter):
    # Preparação dos dados
    data["keys"] = data["keys"].fillna(0)
    data = pd.get_dummies(data)
    data = data.div(data.sum(axis=1), axis="rows")

    # Aplicação do KMeans
    km = KMeans(n_clusters=n_clusters, max_iter=max_iter, n_init=n_init)
    clusters = km.fit_predict(data)

    # Adicionando a coluna de clusters ao DataFrame original
    data["cluster"] = clusters

    # Retorna o DataFrame modificado com a coluna de clusters
    return data


def model_meanshift(dados, n_qualite, samples):
    # Preparação dos dados
    dados["keys"] = dados["keys"].fillna(0)
    dados = pd.get_dummies(dados)
    dados = dados.div(dados.sum(axis=1), axis="rows")

    # Estimando a largura de banda para o MeanShift
    bandwidth = estimate_bandwidth(dados, quantile=n_qualite, n_samples=samples)

    # Aplicação do MeanShift
    ms = MeanShift(bandwidth=bandwidth, bin_seeding=True)
    ms.fit(dados)
    labels = ms.labels_

    # Adicionando a coluna de clusters ao DataFrame original
    dados["cluster"] = labels

    # Calculando o número de clusters únicos
    labels_unique = np.unique(labels)
    n_clusters_ = len(labels_unique)

    print(f"Número estimado de clusters: {n_clusters_}")

    # Retorna o DataFrame modificado com a coluna de clusters e o número de clusters
    return dados, n_clusters_


def list_dates(username):
    # Estabelece conexão com o MongoDB
    client = MongoClient(os.environ["URI_DATABASE"])
    db = client["nomeDoBancoDeDados"]  # Substitua pelo nome correto do banco de dados
    collection = db[f"{username}_data"]

    # Busca todos os documentos na coleção do usuário
    documents = collection.find({}, {"datetime": 1, "site": 1})

    # Processa os documentos para extrair datas e sites únicos
    dates = {}
    for doc in documents:
        datetime_str = doc["datetime"]
        date_str = f"{datetime_str[6:8]}/{datetime_str[4:6]}/{datetime_str[0:4]}"
        time_str = f"{datetime_str[9:11]}:{datetime_str[11:13]}:{datetime_str[13:15]}"
        site = doc.get("site", "Unknown")  # Assume 'Unknown' se o site não estiver presente

        # Adiciona a entrada na lista de datas, com os sites como subentradas
        key = f"{date_str} {time_str}"
        if key not in dates:
            dates[key] = set()
        dates[key].add(site)

    # Converte o dicionário para uma lista formatada
    formatted_dates = []
    for datetime, sites in dates.items():
        date, time = datetime.split()
        formatted_dates.append([date, time, list(sites), datetime.replace(" ", "-")])

    return formatted_dates


def dirs2data(username):
    # Estabelece conexão com o MongoDB
    client = MongoClient(os.environ["URI_DATABASE"])
    db = client["nomeDoBancoDeDados"]  # Substitua pelo nome correto do banco de dados
    collection = db[f"{username}_data"]

    # Busca todos os documentos na coleção do usuário
    documents = collection.find({})

    # Estrutura para armazenar os dados consolidados
    data = []

    # Processa cada documento para extrair e consolidar as informações necessárias
    for doc in documents:
        datetime_str = doc["datetime"]
        date_str = f"{datetime_str[6:8]}/{datetime_str[4:6]}/{datetime_str[0:4]}"
        time_str = f"{datetime_str[9:11]}:{datetime_str[11:13]}:{datetime_str[13:15]}"
        site = doc.get("site", "Unknown")  # Assume 'Unknown' se o site não estiver presente

        # Cria um dicionário para cada conjunto de informações e adiciona à lista de dados
        data.append({
            "date": date_str,
            "hour": time_str,
            "pages": [site],  # Este exemplo assume um único site por documento; ajuste conforme necessário
            "dir": datetime_str.replace("-", "/").replace(" ", "/")  # Estrutura de 'diretório' baseada na data/hora
        })

    return data


def id_generator():
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choice(chars) for _ in range(8))


###############
# plot functions
def make_heatmap(username, collection_name): #substituir collection name pelo nome da coleção
    collection = db[collection_name] #substituir collection name pelo nome da coleção (acho que será duas collections, uma para aúdio e outras para traços)
    # Consulta ao MongoDB para obter dados de trace e audio
    df_trace = pd.DataFrame(list(collection.find({"type": "trace", "username": username})))
    df_audio = pd.DataFrame(list(collection.find({"type": "audio", "username": username})))


    if not df_trace.empty and "image" in df_trace.columns:
        first_image_data = df_trace.iloc[0]["imageData"]  # Ajustar para a estrutura de dados
        im = Image.open(io.BytesIO(base64.b64decode(first_image_data)))
        im0 = base64.b64encode(io.BytesIO(base64.b64decode(first_image_data)).read()).decode('utf-8')

    width, height = im.size
    frames = []
    colorscale = [
        [0, "rgba(255, 255, 255, 0)"],
        [0.15, "rgba(180, 180, 255, 0.45)"],
        [0.25, "rgba(160, 255, 160, 0.55)"],
        [0.45, "rgba(255, 255, 90, 0.65)"],
        [0.65, "rgba(255, 200, 100, 0.75)"],
        [0.85, "rgba(255, 90, 50, 0.85)"],
        [1, "rgba(255, 1, 0, 1)"],
    ]
    for time in sorted(df_trace["time"].unique()):
        filtered_df = df_trace[df_trace["time"] == time]
    for _, row in filtered_df.iterrows():
        plot_df = filtered_df[filtered_df["image"] == row["image"]]
        
        # Preparação dos dados para o heatmap
        x_bins = np.linspace(0, width, 250)
        y_bins = np.linspace(0, height, 250)
        x = plot_df["x"]
        y = (abs(plot_df["y"] - plot_df["scroll"])).values
        histogram, x_edges, y_edges = np.histogram2d(x, y, bins=[x_bins, y_bins])
        data_smoothed = gaussian_filter(histogram, sigma=12)
        
        # Busca o texto do áudio correspondente ao momento, se existir
        audio_text = df_audio[df_audio["time"] == time]["text"].iloc[0] if time in df_audio.time.values else ""
        
        # A imagem já está em Base64, então você pode usá-la diretamente
        img_base64 = row['imageData']  # Isso assume que 'imageData' contém a imagem em Base64

    try:
        frames.append(
            go.Frame(
                data=go.Heatmap(
                    z=data_smoothed,
                    x=x_edges,
                    y=y_edges,
                    colorscale=colorscale,
                    showscale=False,
                    hovertemplate="Posição X: %{x}<br>Posição Y: %{y}",
                ),
                name=str(time),
                layout=dict(
                    images=[
                        dict(
                            source=f"data:image/jpg;base64,{img_base64}",
                            xref="x",
                            yref="y",
                            x=0,
                            y=0,
                            sizex=width,
                            sizey=height,
                            sizing="stretch",
                            opacity=0.5,
                            layer="below"
                        )
                    ],
                    annotations=[
                        dict(
                            x=0.5,
                            y=0.04,
                            xref="paper",
                            yref="paper",
                            text=f"Falado: {audio_text}",
                            font=dict(
                                family="Courier New, monospace",
                                size=18,
                                color="#ffffff",
                            ),
                            bordercolor="#c7c7c7",
                            borderwidth=2,
                            borderpad=8,
                            bgcolor="rgb(36, 36, 36)",
                            opacity=1,
                        )
                    ],
                ),
            )
        )

    except:
        None
    fig = go.Figure(
        data=frames[0].data,
        layout=go.Layout(
            xaxis=dict(
                range=[0, width], autorange=False, rangeslider=dict(visible=False)
            ),
            yaxis=dict(range=[0, height], autorange=False),
            images=[
                dict(
                    source="data:image/jpg;base64,{}".format(im0.decode()),
                    xref="x",
                    yref="y",
                    x=0,
                    y=height,
                    sizex=width,
                    sizey=height,
                    sizing="fill",
                    opacity=1,
                    layer="below",
                )
            ],
        ),
        frames=frames,
    )

    # Configure axes
    fig.update_xaxes(visible=False)

    fig.update_yaxes(
        visible=False,
        # the scaleanchor attribute ensures that the aspect ratio stays constant
        scaleanchor="x",
    )
    fig.update_traces(
        marker=dict(
            size=32,
            color="rgba(255, 255, 0, 0)",
            line=dict(color="rgba(0, 0, 255, 0.003)", width=6),
        ),
        marker_gradient=dict(color="rgba(255, 0, 0, 0.35)", type="radial"),
        selector=dict(type="scatter"),
    )

    # Configure other layout
    fig.update_layout(
        # iterate over frames to generate steps... NB frame name...
        sliders=[
            {
                "steps": [
                    {
                        "args": [
                            [f.name],
                            {
                                "frame": {"duration": 0, "redraw": True},
                                "mode": "immediate",
                            },
                        ],
                        "label": f.name,
                        "method": "animate",
                    }
                    for f in frames
                ],
                "x": 0,
                "y": -0.07,
                "font": {"size": 12},
                "ticklen": 4,
                "currentvalue": {"prefix": "Time(s):", "visible": True},
            }
        ],
        width=width * 0.6,
        height=height * 0.6,
        paper_bgcolor="rgba(33, 37, 41, 1)",
        plot_bgcolor="rgba(0, 0, 0, 0)",
        font=dict(color="white"),
        margin=dict(r=30, t=30, b=140, l=30),
    )

    fig["layout"]["updatemenus"] = [
        {
            "buttons": [
                {
                    "args": [
                        None,
                        {
                            "frame": {"duration": 300, "redraw": True},
                            "fromcurrent": True,
                            "transition": {
                                "duration": 300,
                                "easing": "quadratic-in-out",
                            },
                        },
                    ],
                    "label": "Play",
                    "method": "animate",
                },
                {
                    "args": [
                        [None],
                        {
                            "frame": {"duration": 0, "redraw": True},
                            "mode": "immediate",
                            "transition": {"duration": 0},
                        },
                    ],
                    "label": "Pause",
                    "method": "animate",
                },
            ],
            "direction": "left",
            "pad": {"r": 0, "t": 0, "b": 0, "l": 0},
            "showactive": False,
            "type": "buttons",
            "x": 0.12,
            "xanchor": "right",
            "y": -0.02,
            "yanchor": "top",
            "bgcolor": "rgb(190, 190, 190)",
            "font": {"color": "rgb(0, 0, 0)"},
        }
    ]
    fig.update_xaxes(rangeslider_thickness=0.1)
    plot_as_string = fig.to_html(div_id="plotDiv")

    return plot_as_string


def make_recording(username, db, collection_name_trace, collection_name_image, **kwargs):
    # Buscar dados de trace e imagem do MongoDB
    df_trace = pd.DataFrame(list(db[collection_name_trace].find({"username": username})))

    if df_trace.empty:
        print("Nenhum dado de trace encontrado.")
        return None

    plots = []
    frames = {}

    # Agora, assumindo que cada documento de trace tem um campo 'image_id' referenciando um documento na coleção de imagens
    first_image_doc = db[collection_name_image].find_one({"_id": df_trace.iloc[0]["image_id"]})
    if first_image_doc:
        im = Image.open(io.BytesIO(base64.b64decode(first_image_doc["imageData"])))
        width, height = im.size
    else:
        print("Imagem inicial não encontrada.")
        return None

    # Verificar as primeiras ocorrências dos frames
    for site, group in df_trace.groupby("site"):
        images_ids = group["image_id"].unique()
        frames[site] = {}
        for image_id in images_ids:
            image_doc = db[collection_name_image].find_one({"_id": image_id})
            if image_doc:
                id0 = group[group["image_id"] == image_id].index[0]
                columns = group.loc[id0, ["scroll", "height"]]
                frames[site][str(image_id)] = columns.to_dict()

    full_ims = gen_fullpage_mongodb(username, db, width, height, frames, collection_name_image)



    # Definindo os ícones para cada tipo de interação (ref: https://plotly.com/python/marker-style/)
    type_icon = {
        "freeze": "hourglass",
        "eye": "circle",
        "click": "circle",
        "move": "arrow",
        "keyboard": "hash",
    }

    for site in full_ims.keys():
        fig = go.Figure()
        filtered_df = df_trace[df_trace["site"] == site]

        width, height = full_ims[site].size
        imagem = full_ims[site]
        buffer = BytesIO()
        imagem.save(buffer, format="PNG")  # Ou o formato apropriado da sua imagem
        imagem_base64 = base64.b64encode(buffer.getvalue()).decode()
        image_src = "data:image/png;base64," + imagem_base64

        for type, group in filtered_df.groupby("type"):
            if type in type_icon:
                x = group["x"].values
                y = group["y"].values + group["scroll"].values
                time = group["time"].values
                mode = "lines+markers" if type != "click" else "markers"
                fig.add_trace(
                    go.Scatter(
                        x=x,
                        y=y,
                        mode=mode,
                        name=type,
                        text=[
                            f"Time: {(t // 3600):02d}:{((t % 3600) // 60):02d}:{(t % 60):02d}"
                            for t in time
                        ],
                        hovertemplate=f"Interaction: {type}<br>Site: {site}<br>%{{text}}<br>X: %{{x}}<br>Y: %{{y}}</br>",
                        marker=dict(
                            symbol=type_icon[type],
                            size=10 if type != "click" else 35,
                            angleref="previous",
                        ),
                    )
                )
            else:
                pass
        fig.update_layout(
            title=f"Site: {site}",
            xaxis=dict(
                range=[0, width], autorange=False, rangeslider=dict(visible=False)
            ),
            yaxis=dict(range=[height, 0], autorange=False),
            legend=dict(
                        orientation="h",
                        yanchor="bottom",
                        y=1.01,
                        xanchor="right",
                        x=1,
                        font = dict(color="blue", size=18)
                        ),
            images=[
                dict(
                    source=image_src,
                    xref="paper",  # Usa o sistema de coordenadas relativo ao papel/gráfico
                    yref="paper",
                    x=0,  # Posição no canto inferior esquerdo
                    y=1,  # Posição no canto superior esquerdo
                    sizex=1,  # Estender a imagem para cobrir toda a largura do gráfico
                    sizey=1,  # Estender a imagem para cobrir toda a altura do gráfico
                    sizing="stretch",  # Esticar a imagem para preencher o espaço (alternativas: "contain", "cover")
                    opacity=1,  # Ajustar a opacidade conforme necessário
                    layer="below",  # Colocar a imagem abaixo dos dados do gráfico
                )
            ],
            width=width * 0.6,
            height=height * 0.6,
            margin=dict(l=0, r=0, t=0, b=0),
            paper_bgcolor="rgba(0, 0, 0, 0)",
            plot_bgcolor="rgba(0, 0, 0, 0)",
        )
        fig.update_xaxes(showgrid=False, zeroline=False, visible=False)

        fig.update_yaxes(
            showgrid=False,
            zeroline=False,
            visible=False,
            scaleanchor="x",
        )
        plots.append(fig.to_html(div_id="plotDiv"))
    
    return plots


def gen_fullpage_mongodb(db, collection_name_image, width, height, frames):
    full_ims = {}

    for site, images_data in frames.items():
        # Calcula a altura total considerando o scroll máximo
        height = int(height + max(item["scroll"] for item in images_data.values()))
        compose_im = Image.new("RGB", (width, height), "white")

        for image_id, item in images_data.items():
            # Recupera a imagem do MongoDB usando o ID da imagem
            image_doc = db[collection_name_image].find_one({"_id": image_id}) #criar uma collection para imagem ou deixar a imagem na collection do próprio user?
            if image_doc:
                
                img_data = base64.b64decode(image_doc["imageData"])
                img = Image.open(io.BytesIO(img_data))
                compose_im.paste(img, (0, int(item["scroll"])))

        full_ims[site] = compose_im

    return full_ims


def plot_image(img, figsize_in_inches=(5, 5)):
    fig, ax = plt.subplots(figsize=figsize_in_inches)
    ax.imshow(cv.cvtColor(img, cv.COLOR_BGR2RGB))
    plt.show()

    
