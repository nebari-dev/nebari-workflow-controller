from typing import List

from pydantic import BaseModel


# Models
class KeycloakGroup(BaseModel):
    id: str
    name: str
    path: str


class KeycloakUser(BaseModel):
    username: str
    id: str
    groups: List[KeycloakGroup]
