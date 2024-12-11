package io.itpl.auth.services;

import io.itpl.auth.dto.request.AuthRequest;

public interface AccountManagementService {
  String loginOrRegister(final AuthRequest authRequest);
}
