pub const SYSTEM_DATA_MODEL: &str = "
    _User {
        name:String,
        ext: Json nullable
    }
    
    _Room {
        name: String,
        type: String,
        ext: Json nullable,
        parent: _Room,
        credentials:[_Authorisation],
    }
    
    _Authorisation {
        name: String,
        valid_before: Integer nullable,
        mutate_room: Boolean,
        mutate_room_users: Boolean,
        credentials:[_Credential] ,
        users:[_AuthorAuth],
    }
    
    _AuthorAuth{
        author: _User,
        valid_before : Integer nullable,
    }

    _Credential {
        entity: String,
        valid_before: Integer nullable,
        insert: Boolean,
        mutate_all: Boolean,
        delete_all: Boolean,
    }";
