package io.itpl.auth.exceptions.handler;

import io.itpl.auth.contants.AppConstants;
import io.itpl.auth.dto.response.Response;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.method.HandlerMethod;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

  /*
   * ------------------------------------------------
   *     Some Generic Exception Handler
   * ------------------------------------------------
   * */

  @ExceptionHandler(IllegalAccessException.class)
  @ResponseStatus(HttpStatus.UNAUTHORIZED)
  @ResponseBody
  public ResponseEntity<Response> handleIllegalAccessException(
          IllegalAccessException ex, HandlerMethod handlerMethod) {
    return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body(
                    Response
                            .builder()
                            .status(HttpStatus.UNAUTHORIZED)
                            .statusCode(HttpStatus.UNAUTHORIZED.value())
                            .message(ex.getMessage())
                            .data(
                                    Map.of(
                                            AppConstants.CLASS,
                                            handlerMethod
                                                    .getBeanType()
                                                    .getSimpleName(),
                                            AppConstants.METHOD,
                                            handlerMethod
                                                    .getMethod()
                                                    .getName()))
                            .build());
  }

  @ExceptionHandler(IllegalArgumentException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ResponseBody
  public ResponseEntity<Response> handleIllegalArgumentException(
          IllegalArgumentException ex, HandlerMethod handlerMethod) {
    return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(
                    Response
                            .builder()
                            .status(HttpStatus.BAD_REQUEST)
                            .statusCode(HttpStatus.BAD_REQUEST.value())
                            .message(ex.getMessage())
                            .data(
                                    Map.of(
                                            AppConstants.CLASS,
                                            handlerMethod
                                                    .getBeanType()
                                                    .getSimpleName(),
                                            AppConstants.METHOD,
                                            handlerMethod
                                                    .getMethod()
                                                    .getName()))
                            .build());
  }

  @ExceptionHandler(IllegalStateException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ResponseBody
  public ResponseEntity<Response> handleIIllegalStateException(
          IllegalStateException ex, HandlerMethod handlerMethod) {
    return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(
                    Response
                            .builder()
                            .status(HttpStatus.BAD_REQUEST)
                            .statusCode(HttpStatus.BAD_REQUEST.value())
                            .message(ex.getMessage())
                            .data(
                                    Map.of(
                                            AppConstants.CLASS,
                                            handlerMethod
                                                    .getBeanType()
                                                    .getSimpleName(),
                                            AppConstants.METHOD,
                                            handlerMethod
                                                    .getMethod()
                                                    .getName()))
                            .build());
  }

  @ExceptionHandler(ResourceAccessException.class)
  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  @ResponseBody
  public ResponseEntity<Response> handleNResourceAccessException(
          ResourceAccessException ex, HandlerMethod handlerMethod) {
    return ResponseEntity
            .status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(
                    Response
                            .builder()
                            .status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value())
                            .message(ex.getMessage())
                            .data(
                                    Map.of(
                                            AppConstants.CLASS,
                                            handlerMethod
                                                    .getBeanType()
                                                    .getSimpleName(),
                                            AppConstants.METHOD,
                                            handlerMethod
                                                    .getMethod()
                                                    .getName()))
                            .build());
  }
  @ExceptionHandler(MethodArgumentNotValidException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ResponseBody
  public ResponseEntity<Response> handleValidationException(
          MethodArgumentNotValidException ex, HandlerMethod handlerMethod) {
    Map<String, String> errors = new HashMap<>();
    ex
            .getBindingResult()
            .getAllErrors()
            .forEach(
                    error -> {
                      String fieldName = ((FieldError) error).getField();
                      String errorMessage =
                              error.getDefaultMessage(); // This will contain your custom message
                      errors.put(fieldName, errorMessage);
                    });
    return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(
                    Response
                            .builder()
                            .status(HttpStatus.BAD_REQUEST)
                            .statusCode(HttpStatus.BAD_REQUEST.value())
                            .data(
                                    Map.of(
                                            AppConstants.CLASS,
                                            handlerMethod
                                                    .getBeanType()
                                                    .getSimpleName(),
                                            AppConstants.METHOD,
                                            handlerMethod
                                                    .getMethod()
                                                    .getName(),
                                            AppConstants.ERROR,
                                            errors))
                            .build());
  }

  @ExceptionHandler(ConstraintViolationException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ResponseBody
  public ResponseEntity<Response> handleConstraintViolationException(
          ConstraintViolationException ex, HandlerMethod handlerMethod) {
    return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(
                    Response
                            .builder()
                            .status(HttpStatus.BAD_REQUEST)
                            .statusCode(HttpStatus.BAD_REQUEST.value())
                            .message(ex.getMessage())
                            .data(
                                    Map.of(
                                            AppConstants.CLASS,
                                            handlerMethod
                                                    .getBeanType()
                                                    .getSimpleName(),
                                            AppConstants.METHOD,
                                            handlerMethod
                                                    .getMethod()
                                                    .getName()))
                            .build());
  }

  @ExceptionHandler(UnsupportedOperationException.class)
  @ResponseStatus(HttpStatus.NOT_IMPLEMENTED)
  @ResponseBody
  public ResponseEntity<Response> handleUnsupportedOperationException(
          UnsupportedOperationException ex, HandlerMethod handlerMethod) {
    return ResponseEntity
            .status(HttpStatus.NOT_IMPLEMENTED)
            .body(
                    Response
                            .builder()
                            .status(HttpStatus.NOT_IMPLEMENTED)
                            .statusCode(HttpStatus.NOT_IMPLEMENTED.value())
                            .message(ex.getMessage())
                            .data(
                                    Map.of(
                                            AppConstants.CLASS,
                                            handlerMethod
                                                    .getBeanType()
                                                    .getSimpleName(),
                                            AppConstants.METHOD,
                                            handlerMethod
                                                    .getMethod()
                                                    .getName()))
                            .build());
  }

//  @ExceptionHandler(AccessDeniedException.class)
//  @ResponseStatus(HttpStatus.FORBIDDEN)
//  @ResponseBody
//  public ResponseEntity<Response> handleAccessDeniedException(AccessDeniedException ex) {
//    return ResponseEntity
//            .status(HttpStatus.FORBIDDEN)
//            .body(
//                    Response
//                            .builder()
//                            .status(HttpStatus.FORBIDDEN)
//                            .statusCode(HttpStatus.FORBIDDEN.value())
//                            .message("You don't have access to perform this action.")
//                            .build());
//  }
//
//  @ExceptionHandler(AuthenticationException.class)
//  @ResponseStatus(HttpStatus.UNAUTHORIZED)
//  @ResponseBody
//  public ResponseEntity<Response> handleAuthenticationException(AuthenticationException ex) {
//    return ResponseEntity
//            .status(HttpStatus.UNAUTHORIZED)
//            .body(
//                    Response
//                            .builder()
//                            .status(HttpStatus.UNAUTHORIZED)
//                            .statusCode(HttpStatus.UNAUTHORIZED.value())
//                            .message("Authentication needed: Please authenticate to continue.")
//                            .build());
//  }
}
