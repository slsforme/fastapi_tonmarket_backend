from sqlalchemy.ext.automap import automap_base
from .database import engine

Base = automap_base()

# to learn
Base.prepare(engine, reflect=False)

User = Base.classes.users  
Product = Base.classes.products
ProductType = Base.classes.product_types

