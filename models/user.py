from dataclasses import dataclass


@dataclass
class User:
    id: int
    username: str
    email: str

    @classmethod
    def from_database_row(cls, row):
        if row is None:
            return None

        return cls(
            id=row["id"],
            username=row["username"],
            email=row["email"],
        )