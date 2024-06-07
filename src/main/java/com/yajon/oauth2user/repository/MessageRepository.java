package com.yajon.oauth2user.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.yajon.oauth2user.entity.MessageEntity;

@Repository
public interface MessageRepository  extends JpaRepository<MessageEntity, Long> {

    @Query("SELECT m FROM MessageEntity m WHERE m.user.id = :id")
    List<MessageEntity> findByUserId(@Param("id") Long id);
}
