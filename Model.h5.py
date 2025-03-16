from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, MaxPooling1D, Flatten
import numpy as np

# Generate dummy input data: 100 samples, each with 32 features reshaped for CNN
X_dummy = np.random.rand(100, 32, 1)
y_dummy = np.random.randint(0, 5, size=(100,))
y_dummy = np.eye(5)[y_dummy]  # One-hot encoding for 5 classes

# Define a basic CNN model
model = Sequential([
    Conv1D(32, 3, activation='relu', input_shape=(32, 1)),
    MaxPooling1D(2),
    Flatten(),
    Dense(64, activation='relu'),
    Dense(5, activation='softmax')  # Output layer for 5 classes
])

model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])

# Train the model
model.fit(X_dummy, y_dummy, epochs=3, batch_size=16)

# Save the model
model.save("Model.h5")
model.save("Model.keras")

