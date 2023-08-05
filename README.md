# Network Intrusion Detection System

## METHODOLOGY

### **1. Technologies Used**
- Python
- Pandas
- Numpy
- Sckit-Learn
- Streamlit
- Plotly Express

### **2. Classification**
Classification is a supervised learning technique for assigning predefined labels or classes to input data based on their features. The goal of classification is to build a predictive model that can accurately classify new, unseen data instances into the correct classes or categories.
Classification is widely used in various domains such as spam detection, sentiment analysis, disease diagnosis, and image recognition.

### **3. Feature Selection**
For include choice, we utilized connection examination and element significance positioning methods to distinguish and choose applicable highlights from the dataset. The goal was to lessen dimensionality, work on model execution, and upgrade interpretability. To start with, we directed connection investigation to survey the connections between the highlights and the objective variable. Highlights areas of strength for showing or high significance scores were held for additional examination. This interaction permitted us to zero in on the most enlightening elements while taking out repetitive or irrelevant ones. Furthermore, include significance positioning strategies, for example, tree-based techniques or data gain, were utilized to rank the elements in view of their pertinence. By taking into account both relationship examination and component significance, we guaranteed that the chose highlights caught the main parts of the organization associations.

### **4. Model Training**
To address the errand of interruption identification, we assessed various AI calculations known for their adequacy in this area. In particular, we considered Strategic Relapse, K-Closest Neighbors (KNN), Backing Vector Machines (SVM), Choice Tree, and Irregular Timberland. These calculations were picked in view of their capacity to deal with the dataset qualities and their laid out utilization in interruption identification research.
The models were prepared utilizing the preprocessed dataset. We split the information into a preparation set, involving 70% of the dataset, and an approval set, containing the leftover 30%. 

### **5. Model Selection**
After Training and testing all the models, the comparison was done using a bar graph to compare the Accuracy Score, Precision, Recall, F1 Score and AUC ROC Score.
It is evident from the Graph that Random Forest Classifier is best suited for the Classification of our dataset.
Hence, we will use this dataset for further predictions.

### **7. Web Application Development**
In this project, we employed Streamlit, a popular Python library for building interactive web applications, to implement the user interface and functionality of our web application for network intrusion detection. The following steps outline the methodology used in developing the web application.

### **8. Data Visualization and User Interface**
First, we utilized Plotly Express’s data visualization capabilities to create informative and interactive visualizations of the network intrusion detection results. We designed the user interface to provide an intuitive and user-friendly experience for users to interact with the application. Streamlit's built-in components, such as sliders, dropdowns, and checkboxes, were leveraged to enable user input and selection.
