package com.yajon.oauth2user.service.impl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.stereotype.Service;

import com.yajon.oauth2user.entity.MessageEntity;
import com.yajon.oauth2user.entity.UserEntity;
import com.yajon.oauth2user.repository.MessageRepository;
import com.yajon.oauth2user.repository.UserRepository;
import com.yajon.oauth2user.service.MessageService;

import jakarta.transaction.Transactional;

@Transactional
@Service
public class MessageServiceImpl implements MessageService {
    @Autowired
    UserRepository userRepository;
    @Autowired
    MessageRepository messageRepository;

    @Override
    public MessageEntity createMessage(String context, Long userId) throws Exception {
        UserEntity user = userRepository.getReferenceById(userId);

        MessageEntity message = new MessageEntity(context, user);

        messageRepository.save(message);
        return message;
    }

    @Override
    public List<MessageEntity> listMessage(Long userId) throws Exception {
        return messageRepository.findByUserId(userId);
    }

    @Override
    public MessageEntity showMessage(Long id, Long userId) throws Exception {
        MessageEntity message = messageRepository.getReferenceById(id);
        if (message.getUser().getId() != userId) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
        }

        return message;
    }

    @Override
    public void deleteMessage(Long id, Long userId) throws Exception {
        MessageEntity message = messageRepository.getReferenceById(id);
        if (message.getUser().getId() != userId) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
        }

        messageRepository.delete(message);
    }


}
