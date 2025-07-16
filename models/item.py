from pydantic import BaseModel

class Item(BaseModel):
    name: str
    description: str = None
    price: float
    tax: float = None
    tags: list[str] = []
    out_of_stock: bool = False