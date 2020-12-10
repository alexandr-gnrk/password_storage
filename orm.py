import bcrypt

from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base


engine = create_engine(
    'sqlite:///users.db',
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

    def __repr__(self):
       return "<User(user_id='%s', full_name='%s')>" % (
                            self.user_id, self.full_name)

Base.metadata.create_all(engine)


def check_credential(login, password):
    user = session.query(User).\
        filter(User.login == login).\
        first()
    if user is None:
        return None

    password_bytes = bytes(password, encoding='ascii')
    if bcrypt.checkpw(password_bytes, user.password_hash):
        return user
    else:
        return None


def create_user(full_name, email, login, password):
    password_bytes = bytes(password, encoding='ascii')
    hashed_passsword = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    user = User( 
        full_name=full_name,
        email=email,
        login=login,
        password_hash=hashed_passsword)
    session.add(user)
    session.commit()
    return user