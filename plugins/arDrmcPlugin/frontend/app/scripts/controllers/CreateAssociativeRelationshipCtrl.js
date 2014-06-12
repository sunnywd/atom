'use strict';

module.exports = function ($scope, $modalInstance, InformationObjectService, TaxonomyService, id, sources, target) {

  // HACK: form scoping issue within modals, see
  // - http://stackoverflow.com/a/19931221/2628967
  // - https://github.com/angular-ui/bootstrap/issues/969
  $scope.modalContainer = {};

  // New record?
  $scope.new = id === null;

  // Associative relationships types
  TaxonomyService.getTerms('ASSOCIATIVE_RELATIONSHIP_TYPES').then(function (data) {
    $scope.modalContainer.types = data.terms;
  });

  // Make modal resolves accessible from the model
  $scope.sources = sources;
  $scope.target = target;

  $scope.submit = function () {
    if ($scope.modalContainer.form.$invalid) {
      return;
    }
    // TODO: this method will only accept one source for now
    var options = {};
    if (angular.isDefined($scope.modalContainer.obj.note)) {
      options.note = $scope.modalContainer.obj.note;
    }
    InformationObjectService.associate(sources[0].id, target.id, $scope.modalContainer.obj.type, options).then(function () {
      $modalInstance.close($scope.modalContainer.obj.type);
    }, function (reason) {
      $modalInstance.dismiss(reason);
    });
  };

  $scope.cancel = function () {
    $modalInstance.dismiss('Cancel');
  };

};
