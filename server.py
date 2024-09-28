from flask import Flask, request, jsonify
import joblib
import numpy as np
import cv2
import os
from keras.api.models import load_model
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin 
from flask_cors import CORS



app = Flask(__name__)

CORS(app)


@app.route('/scan', methods=['POST'])
def scan_page():
    if request.content_type != 'application/json':
        return jsonify({"error": "Content-Type must be application/json"}), 415
    
    data = request.json
    url = data.get('url')

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        # Fetch the page content
        response = requests.get(url)
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch the page"}), 400

        # Parse the HTML and extract image URLs
        soup = BeautifulSoup(response.content, 'html.parser')
        img_tags = soup.find_all('img')
        img_urls = [urljoin(response.url, img['src']) for img in img_tags if 'src' in img.attrs]
        # List to hold results
        malicious_images = []

        # Check each image for malware
        for img_url in img_urls:
            try:
                # Download the image
                img_data = requests.get(img_url).content
                img_array = np.frombuffer(img_data, np.uint8)
                img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
                img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
                if img is not None:
                  img = cv2.resize(img, (IMG_SIZE, IMG_SIZE))
                else:
                 logging.error(f"Unable to read the image from {img_url}")
                
                
                img = np.array(img) / 255.0  # Normalize the image
                img = np.reshape(img, (1, IMG_SIZE, IMG_SIZE, 3))  # Reshape for the model input

                # Make prediction
                prediction = malware_model.predict(img)
                predicted_class = np.argmax(prediction, axis=1)[0]

                # Check if the image is malicious
                if predicted_class == 1:  # Assuming 1 corresponds to malicious
                    malicious_images.append(img_url)

            except Exception as e:
                logging.error("Error processing image %s: %s", img_url, str(e))

        # Prepare the response
        if malicious_images:
            return jsonify({
                "message": "Malicious content detected!",
                "malicious_images": malicious_images
            }), 200
        else:
            return jsonify({"message": "The site is safe."}), 200

    except Exception as e:
        logging.error("Error during page scanning: %s", str(e))
        return jsonify({"error": "Internal server error"}), 500


# Load URL classification model
url_model = joblib.load('url_classifier.pkl')
vectorizer = joblib.load('vectorizer.pkl')

# Load malware classification model
malware_model = load_model('C:\\Users\\ganza\\OneDrive\\Documents\\trust-armor\\malware_classifier.h5')

# Define image size
IMG_SIZE = 128

logging.basicConfig(level=logging.INFO)

@app.route('/predict', methods=['POST'])
def predict():
    logging.info("Request method: %s", request.method)
    logging.info("Request URL: %s", request.url)
    
    if request.content_type != 'application/json':
        return jsonify({"error": "Content-Type must be application/json"}), 415
    
    data = request.json
    url = data.get('url')

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        url_vectorized = vectorizer.transform([url])
        prediction = url_model.predict(url_vectorized)
        label_mapping = {0: 'benign', 1: 'malicious'}
        result = label_mapping.get(prediction[0], 'unknown')
        return jsonify({'result': result})
    except Exception as e:
        logging.error("Error during URL prediction: %s", str(e))
        return jsonify({"error": "Internal server error"}), 500

@app.route('/train', methods=['POST'])
def train():
    try:
        train_model() 
        return jsonify({'message': 'Model trained successfully'}), 200
    except Exception as e:
        logging.error("Error training model: %s", str(e))
        return jsonify({"error": "Internal server error"}), 500

@app.route('/predict_malware', methods=['POST'])
def predict_malware():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        # Read the image and preprocess it
        img_path = os.path.join('/tmp', file.filename)  # Save file temporarily
        file.save(img_path)
        
        img = cv2.imread(img_path)
        img = cv2.resize(img, (IMG_SIZE, IMG_SIZE))
        img = np.array(img) / 255.0  # Normalize the image
        img = np.reshape(img, (1, IMG_SIZE, IMG_SIZE, 3))  # Reshape for the model input
        
        # Make prediction
        prediction = malware_model.predict(img)
        predicted_class = np.argmax(prediction, axis=1)[0]
        
        # Define your categories here (same as in your training code)
        CATEGORIES = ['Vilsel', 'VBKrypt', 'VBA', 'Stantinko', 'Snarasite', 'Sality', 'Regrun', 
                      'Neshta', 'Neoreklami', 'MultiPlug', 'Lolyda.AA2', 'Lolyda.AA1', 
                      'InstallCore', 'Injector', 'Hlux', 'HackKMS', 'Fasong', 'Fakerean', 
                      'Expiro', 'Elex', 'Dinwod', 'Dialplatform.B', 'C2LOP.gen!g', 
                      'BrowseFox', 'Autorun', 'Androm', 'Amonetize', 'Alueron.gen!J', 
                      'Allaple', 'Agent', 'Adposhel', 'media']
        
        result = CATEGORIES[predicted_class]
        
        return jsonify({'result': result})

    except Exception as e:
        logging.error("Error during malware prediction: %s", str(e))
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
