package com.yajon.oauth2user.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "message")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class MessageEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private String content;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(
        name = "user_id", 
        nullable = false, 
        foreignKey = @ForeignKey(name = "user_message_fk"))
    private UserEntity user;

    public MessageEntity(String content, UserEntity user) {
        this.content = content;
        this.user = user;
    }
}
