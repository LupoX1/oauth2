package com.codersdungeon.authserver.usermanagement;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "authorities")
public class Authority implements Serializable {

    @EmbeddedId
    private AuthorityPrimaryKey primaryKey;

    @Column
    private String description;

    public AuthorityPrimaryKey getPrimaryKey() {
        return primaryKey;
    }

    public void setPrimaryKey(AuthorityPrimaryKey primaryKey) {
        this.primaryKey = primaryKey;
    }

    @Embeddable
    public static class AuthorityPrimaryKey implements Serializable {
        @ManyToOne
        @JoinColumn(name = "username")
        private User username;

        @Column(length = 50)
        private String authority;

        public User getUsername() {
            return username;
        }

        public void setUsername(User username) {
            this.username = username;
        }

        public String getAuthority() {
            return authority;
        }

        public void setAuthority(String authority) {
            this.authority = authority;
        }
    }
}
