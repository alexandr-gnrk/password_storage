import bcrypt

from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base


engine = create_engine(
    'sqlite:///data/users.db',
    connect_args={'check_same_thread': False})
Base = declarative_base()
session = sessionmaker(bind=engine)()


class User(Base):
    __tablename__ = 'users'
    __table_args__ = {'sqlite_autoincrement': True}

    
    # user_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, primary_key=True)
    full_name = Column(String)
    email = Column(String)
    login = Column(String)
    password_hash = Column(String)
    mobile_phone_hash = Column(String)
    nonce = Column(String)
    version = Column(Integer)
    compromised = Column(Boolean)

    def __repr__(self):
       return "<User(user_id='%s', full_name='%s')>" % (
                            self.user_id, self.full_name)

Base.metadata.create_all(engine)


def check_credential(login, password):
    user = get_user(login)
    if user is None:
        return None

    password_bytes = bytes(password, encoding='ascii')
    if bcrypt.checkpw(password_bytes, user.password_hash):
        return user
    else:
        return None

def get_user(login):
    return session.query(User).\
        filter(User.login == login).\
        first()

def create_user(
        full_name, email, login, password, 
        mobile_phone_hash, nonce,
        version=1, compromised=False):
    password_bytes = bytes(password, encoding='ascii')
    hashed_passsword = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    user = User( 
        full_name=full_name,
        email=email,
        login=login,
        password_hash=hashed_passsword,
        mobile_phone_hash=mobile_phone_hash,
        nonce=nonce,
        version=version,
        compromised=compromised)
    session.add(user)
    session.commit()
    return user