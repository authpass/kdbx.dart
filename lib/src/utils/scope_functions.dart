/// https://github.com/YusukeIwaki/dart-kotlin_flavor/blob/74593dada94bdd8ca78946ad005d3a2624dc833f/lib/scope_functions.dart
/// MIT license: https://github.com/YusukeIwaki/dart-kotlin_flavor/blob/74593dada94bdd8ca78946ad005d3a2624dc833f/LICENSE

ReturnType run<ReturnType>(ReturnType operation()) {
  return operation();
}

extension ScopeFunctionsForObject<T extends Object> on T {
  ReturnType let<ReturnType>(ReturnType operationFor(T self)) {
    return operationFor(this);
  }

  T also(void operationFor(T self)) {
    operationFor(this);
    return this;
  }
}
