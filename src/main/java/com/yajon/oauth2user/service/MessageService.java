package com.yajon.oauth2user.service;

import java.util.List;

import com.yajon.oauth2user.entity.MessageEntity;

public interface MessageService {
    public MessageEntity createMessage(String message, Long userId) throws Exception;

    public List<MessageEntity> listMessage(Long userId) throws Exception;

    public MessageEntity showMessage(Long id, Long userId) throws Exception;

    public void deleteMessage(Long id, Long userId) throws Exception;
}
