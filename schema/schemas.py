
def indivual_serial(item) -> dict:
    return {
        "id": str(item["_id"]),
        "name": item["name"],
        "description": item["description"],
        "price": item["price"],
        "tax": item["tax"],
        "tags": item["tags"],
        "out_of_stock": item["out_of_stock"],
    }

def list_serial(items) -> list:
    return [indivual_serial(item) for item in items]