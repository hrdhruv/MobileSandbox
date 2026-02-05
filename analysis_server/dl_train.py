import pandas as pd
import torch
from torch.utils.data import TensorDataset, DataLoader
from dl_model import MalwareNet

CSV_PATH = "dataset/data.csv"
MODEL_PATH = "dl_model.pt"

df = pd.read_csv(CSV_PATH)

y = df["Class"].values
X = df.drop(columns=["Class"]).values

X = torch.tensor(X, dtype=torch.float32)
y = torch.tensor(y, dtype=torch.float32).unsqueeze(1)

dataset = TensorDataset(X, y)
loader = DataLoader(dataset, batch_size=64, shuffle=True)

model = MalwareNet(X.shape[1])
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
loss_fn = torch.nn.BCELoss()

for epoch in range(5):
    for xb, yb in loader:
        pred = model(xb)
        loss = loss_fn(pred, yb)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

    print(f"Epoch {epoch+1}, Loss {loss.item():.4f}")

torch.save(model.state_dict(), MODEL_PATH)
print("Model trained and saved.")
