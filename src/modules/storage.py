class Storage:
  storage: dict[str, int]

  def __init__(self):
    self.storage = {}

  def add(self, ip: str):
    self.storage[ip] = self.storage.get(ip, 0) + 1
  
  def show(self):
    print(self.storage.__str__())

storage = Storage()