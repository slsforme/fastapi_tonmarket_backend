from sqlalchemy.ext.automap import automap_base
from .database import engine

Base = automap_base()

# to learn
Base.prepare(engine, reflect=False)

User = Base.classes.users  
Role = Base.classes.roles
Log = Base.classes.logs
SmartContract = Base.classes.smart_contracts

